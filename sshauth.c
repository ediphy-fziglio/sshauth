/*
 * sshauth: run a command through the sshauth unix socket.
 *
 * Request:  "SSHA" | u16 version (1) | u16 len | command line (len <= 4096)
 * Reply:    "ERR!" | u16 len | message (len <= 1024)          -> exit 1
 *           "OKAY" + errfd passed with SCM_RIGHTS
 * Then stdin -> socket, socket -> stdout, and errfd carries:
 *           "EXIT" | i32 code
 *           "TEXT" | u16 len | text (len <= 1024)              -> stderr
 * All integers are big endian.
 *
 * Build: cc -O2 -Wall -Wextra -o sshauth sshauth.c
 */
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef SOCK_PATH
#define SOCK_PATH "/root/.ssh/sshauth.sock"
#endif
#define MAX_CMD 4096
#define MAX_MSG 1024
/* Exit code for local and protocol errors, as ssh does. */
#define EXIT_LOCAL 255

static void die(const char *what)
{
    fprintf(stderr, "sshauth: %s: %s\n", what, strerror(errno));
    exit(EXIT_LOCAL);
}

static void die_proto(const char *what)
{
    fprintf(stderr, "sshauth: protocol error: %s\n", what);
    exit(EXIT_LOCAL);
}

static void write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            die("write");
        }
        p += n;
        len -= (size_t)n;
    }
}

/* Reads exactly len bytes; returns 0 on success, -1 on EOF before len. */
static int read_all(int fd, void *buf, size_t len)
{
    char *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            die("read");
        }
        if (n == 0)
            return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static uint16_t get_u16(const unsigned char *p)
{
    return (uint16_t)(p[0] << 8 | p[1]);
}

static int32_t get_i32(const unsigned char *p)
{
    return (int32_t)((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
                     (uint32_t)p[2] << 8 | (uint32_t)p[3]);
}

/*
 * Reads the 4-byte reply tag with recvmsg, picking up a file descriptor
 * passed as ancillary data on any of those bytes. Returns the fd or -1.
 */
static int recv_tag(int sock, unsigned char tag[4])
{
    size_t got = 0;
    int fd = -1;

    while (got < 4) {
        union {
            struct cmsghdr hdr;
            char buf[CMSG_SPACE(sizeof(int))];
        } ctrl;
        struct iovec iov = { tag + got, 4 - got };
        struct msghdr msg = { 0 };
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl.buf;
        msg.msg_controllen = sizeof(ctrl.buf);

        ssize_t n = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            die("recvmsg");
        }
        if (n == 0)
            die_proto("connection closed before reply");
        if (msg.msg_flags & MSG_CTRUNC)
            die_proto("ancillary data truncated");

        for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
                c->cmsg_len == CMSG_LEN(sizeof(int))) {
                if (fd >= 0)
                    close(fd);
                memcpy(&fd, CMSG_DATA(c), sizeof(int));
            }
        }
        got += (size_t)n;
    }
    return fd;
}

/* Builds the command line: argv[1..] joined by single spaces. */
static size_t build_cmd(int argc, char **argv, char *out)
{
    size_t len = 0;
    for (int i = 1; i < argc; i++) {
        size_t n = strlen(argv[i]) + (i > 1);
        if (len + n > MAX_CMD) {
            fprintf(stderr, "sshauth: command line longer than %d bytes\n", MAX_CMD);
            exit(EXIT_LOCAL);
        }
        if (i > 1)
            out[len++] = ' ';
        memcpy(out + len, argv[i], strlen(argv[i]));
        len += strlen(argv[i]);
    }
    return len;
}

/*
 * Buffer for messages read from errfd. The largest message is
 * "TEXT" + 2 + MAX_MSG bytes.
 */
static unsigned char ebuf[6 + MAX_MSG];
static size_t elen;

/*
 * Handles every complete message in ebuf. Returns 1 and sets *code
 * when an EXIT message was seen, 0 otherwise.
 */
static int handle_err_msgs(int32_t *code)
{
    for (;;) {
        if (elen < 4)
            return 0;
        if (memcmp(ebuf, "EXIT", 4) == 0) {
            if (elen < 8)
                return 0;
            *code = get_i32(ebuf + 4);
            return 1;
        }
        if (memcmp(ebuf, "TEXT", 4) != 0)
            die_proto("unknown message on errfd");
        if (elen < 6)
            return 0;
        size_t len = get_u16(ebuf + 4);
        if (len > MAX_MSG)
            die_proto("TEXT message too long");
        if (elen < 6 + len)
            return 0;
        write_all(STDERR_FILENO, ebuf + 6, len);
        memmove(ebuf, ebuf + 6 + len, elen - 6 - len);
        elen -= 6 + len;
    }
}

int main(int argc, char **argv)
{
    static char cmd[MAX_CMD];
    unsigned char hdr[8];
    unsigned char tag[4];
    char buf[16384];

    signal(SIGPIPE, SIG_IGN);

    size_t cmd_len = build_cmd(argc, argv, cmd);

    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0)
        die("socket");
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        die("connect " SOCK_PATH);

    memcpy(hdr, "SSHA", 4);
    hdr[4] = 0;
    hdr[5] = 1;
    hdr[6] = (unsigned char)(cmd_len >> 8);
    hdr[7] = (unsigned char)cmd_len;
    write_all(sock, hdr, sizeof(hdr));
    write_all(sock, cmd, cmd_len);

    int errfd = recv_tag(sock, tag);
    if (memcmp(tag, "ERR!", 4) == 0) {
        unsigned char lenb[2];
        char msg[MAX_MSG];
        if (read_all(sock, lenb, 2) < 0)
            die_proto("truncated ERR! reply");
        size_t len = get_u16(lenb);
        if (len > MAX_MSG)
            die_proto("ERR! message too long");
        if (read_all(sock, msg, len) < 0)
            die_proto("truncated ERR! reply");
        write_all(STDERR_FILENO, msg, len);
        if (len == 0 || msg[len - 1] != '\n')
            write_all(STDERR_FILENO, "\n", 1);
        return 1;
    }
    if (memcmp(tag, "OKAY", 4) != 0)
        die_proto("unknown reply");
    if (errfd < 0)
        die_proto("OKAY without a file descriptor");

    /*
     * fds[0] stdin, fds[1] socket, fds[2] errfd; fd = -1 once closed,
     * which poll ignores.
     */
    struct pollfd fds[3] = {
        { STDIN_FILENO, POLLIN, 0 },
        { sock, POLLIN, 0 },
        { errfd, POLLIN, 0 },
    };
    int exited = 0;
    int32_t code = 0;

    /*
     * ASSUMPTION: the EXIT message can arrive before the last command
     * output on the socket, so after EXIT we keep copying the socket to
     * stdout until the server closes it, and stop reading stdin.
     */
    while (fds[1].fd >= 0 || (!exited && fds[2].fd >= 0)) {
        if (poll(fds, 3, -1) < 0) {
            if (errno == EINTR)
                continue;
            die("poll");
        }

        if (fds[0].revents) {
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n < 0 && errno != EINTR)
                die("read stdin");
            if (n == 0) {
                /* Pass EOF on so the remote command sees it. */
                shutdown(sock, SHUT_WR);
                fds[0].fd = -1;
            } else if (n > 0 && fds[1].fd >= 0) {
                write_all(sock, buf, (size_t)n);
            }
        }

        if (fds[1].revents) {
            ssize_t n = read(sock, buf, sizeof(buf));
            if (n < 0 && errno != EINTR)
                die("read socket");
            if (n == 0)
                fds[1].fd = -1;
            else if (n > 0)
                write_all(STDOUT_FILENO, buf, (size_t)n);
        }

        if (fds[2].revents) {
            ssize_t n = read(errfd, ebuf + elen, sizeof(ebuf) - elen);
            if (n < 0 && errno != EINTR)
                die("read errfd");
            if (n == 0) {
                if (elen > 0)
                    die_proto("truncated message on errfd");
                fds[2].fd = -1;
            } else if (n > 0) {
                elen += (size_t)n;
                if (handle_err_msgs(&code)) {
                    exited = 1;
                    fds[0].fd = -1;
                    fds[2].fd = -1;
                }
            }
        }
    }

    if (!exited)
        die_proto("connection closed without EXIT");
    return code;
}
