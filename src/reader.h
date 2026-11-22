/*
 * Odczyt w dwóch przebiegach: reader_scan zbiera metadane pliku, a
 * reader_merge podaje pakiety ze wszystkich plików w kolejności czasu
 * (scalanie k-drogowe).
 */
#ifndef PA_READER_H
#define PA_READER_H

#include <stdint.h>

typedef struct {
    const char *path;
    int      ok;              /* plik otwarty poprawnie */
    char     err[256];        /* komunikat błędu (jeśli wystąpił) */
    int      read_error;      /* błąd w trakcie odczytu (np. ucięty plik) */
    int      dlt;             /* typ warstwy łącza */
    char     dlt_name[64];
    uint32_t snaplen;
    uint64_t packets;
    uint64_t bytes;           /* suma długości ramek w sieci */
    uint64_t cap_bytes;       /* suma długości przechwyconych */
    int64_t  first_ns, last_ns;
    int      unordered;       /* znaczniki czasu nie są monotoniczne */
} input_file_t;

typedef void (*reader_cb)(void *ctx, int file_idx, int dlt, int64_t ts_ns,
                          uint32_t caplen, uint32_t wirelen, const uint8_t *data);

/* Przebieg 1 dla jednego pliku. Zwraca 0 gdy plik da się czytać. */
int reader_scan(input_file_t *f);

/* Przebieg 2: wywołuje cb dla każdego pakietu w kolejności czasowej.
 * Zwraca liczbę dostarczonych pakietów. */
uint64_t reader_merge(input_file_t *files, int nfiles, reader_cb cb, void *ctx);

#endif
