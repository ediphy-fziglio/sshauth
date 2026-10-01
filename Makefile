CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra
PREFIX ?= /usr/local

sshauth: sshauth.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

install: sshauth
	install -D -m 755 sshauth $(DESTDIR)$(PREFIX)/bin/sshauth

clean:
	rm -f sshauth

.PHONY: install clean
