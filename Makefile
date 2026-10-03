CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra
GO ?= go
PREFIX ?= /usr/local

all: sshauth sshauthd

sshauth: sshauth.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

sshauthd: go.mod $(wildcard cmd/sshauthd/*.go sshauthproto/*.go)
	$(GO) build -o $@ ./cmd/sshauthd

install: sshauth sshauthd
	install -D -m 755 sshauth $(DESTDIR)$(PREFIX)/bin/sshauth
	install -D -m 755 sshauthd $(DESTDIR)$(PREFIX)/sbin/sshauthd

check: sshauth
	./tests.sh

clean:
	rm -f sshauth sshauthd

.PHONY: all install check clean
