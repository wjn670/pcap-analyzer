# pcap-analyzer - analiza ruchu TCP/UDP z plików pcap z raportem PDF i wykresami PNG
#
# Zależności: libpcap, cairo (np. Debian/Ubuntu: libpcap-dev libcairo2-dev pkg-config)
#
#   make            - kompilacja programu
#   make test       - testy jednostkowe i testy całościowe (end-to-end)
#   make sanitize   - kompilacja z AddressSanitizer/UBSan i uruchomienie testów
#   make install    - instalacja do $(PREFIX)/bin

CC         ?= cc
PKG_CONFIG ?= pkg-config
PREFIX     ?= /usr/local

CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Wshadow -Wpointer-arith \
          -Wstrict-prototypes -Wmissing-prototypes -Wno-unused-parameter

ifeq ($(shell uname -s),Darwin)
CFLAGS += -D_DARWIN_C_SOURCE
endif

CAIRO_CFLAGS := $(shell $(PKG_CONFIG) --cflags cairo)
CAIRO_LIBS   := $(shell $(PKG_CONFIG) --libs cairo)
PCAP_CFLAGS  := $(shell $(PKG_CONFIG) --cflags libpcap 2>/dev/null || pcap-config --cflags 2>/dev/null)
PCAP_LIBS    := $(shell $(PKG_CONFIG) --libs libpcap 2>/dev/null || pcap-config --libs 2>/dev/null || echo -lpcap)

ALL_CFLAGS = $(CFLAGS) $(CAIRO_CFLAGS) $(PCAP_CFLAGS)
LIBS       = $(CAIRO_LIBS) $(PCAP_LIBS) -lm

BIN   = pcap-analyzer
BUILD = build

CORE_SRC = src/util.c src/decode.c src/reader.c src/flow.c src/dns.c \
           src/analysis.c src/anomaly.c src/chart.c src/figures.c \
           src/pdfdoc.c src/report.c src/export.c
CORE_OBJ = $(CORE_SRC:src/%.c=$(BUILD)/%.o)
MAIN_OBJ = $(BUILD)/main.o
HEADERS  = $(wildcard src/*.h)

.PHONY: all clean test unit e2e sanitize install

all: $(BIN)

$(BIN): $(CORE_OBJ) $(MAIN_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

$(BUILD)/%.o: src/%.c $(HEADERS) | $(BUILD)
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

$(BUILD):
	mkdir -p $(BUILD)

# --- narzędzia testowe -------------------------------------------------

$(BUILD)/pcapgen: tools/pcapgen.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< -lm

$(BUILD)/unit_tests: tests/unit_tests.c $(CORE_OBJ) $(HEADERS) | $(BUILD)
	$(CC) $(ALL_CFLAGS) -Isrc -o $@ tests/unit_tests.c $(CORE_OBJ) $(LIBS) $(LDFLAGS)

unit: $(BUILD)/unit_tests
	./$(BUILD)/unit_tests

e2e: $(BIN) $(BUILD)/pcapgen
	sh tests/e2e.sh ./$(BIN) ./$(BUILD)/pcapgen

test: unit e2e

sanitize:
	$(MAKE) clean
	$(MAKE) test CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" \
	             LDFLAGS="-fsanitize=address,undefined"

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -rf $(BUILD) $(BIN) tests/out
