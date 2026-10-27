# weld: build with the goose on PATH, or GOOSE=/path/to/goose.
GOOSE ?= goose
PREFIX ?= /usr/local
SOURCES := $(wildcard src/*.goose) $(wildcard src/*.c) src/weld.build
FUZZ ?= 1000

.PHONY: all test quick format install uninstall clean help

all: weld

weld: $(SOURCES)
	$(GOOSE) build src/weld.goose -o $@

test:                  ## readelf and GNU ld comparisons, links that run, and FUZZ corrupted inputs
	GOOSE=$$(command -v $(GOOSE)) python3 tests/test.py --fuzz $(FUZZ)

quick:                 ## the same, with 50 corrupted inputs
	GOOSE=$$(command -v $(GOOSE)) python3 tests/test.py --fuzz 50

format:                ## check the standard layout (goose format), failing if a file is not in it
	$(GOOSE) format --check .

install: weld          ## weld and ld.weld (clang -fuse-ld) into $(PREFIX)/bin, and libexec/weld/ld (gcc -B)
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/libexec/weld
	install -m 755 weld $(DESTDIR)$(PREFIX)/bin/weld
	ln -sf weld $(DESTDIR)$(PREFIX)/bin/ld.weld
	ln -sf ../../bin/weld $(DESTDIR)$(PREFIX)/libexec/weld/ld

uninstall:             ## remove them again
	rm -f $(DESTDIR)$(PREFIX)/bin/weld $(DESTDIR)$(PREFIX)/bin/ld.weld $(DESTDIR)$(PREFIX)/libexec/weld/ld
	-rmdir $(DESTDIR)$(PREFIX)/libexec/weld 2>/dev/null

clean:
	rm -f weld

help:
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'
