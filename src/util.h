#ifndef PA_UTIL_H
#define PA_UTIL_H

#include <stddef.h>
#include <stdint.h>

#define PA_NAME    "pcap-analyzer"
#define PA_VERSION "1.0.0"

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define PA_MIN(a, b) ((a) < (b) ? (a) : (b))
#define PA_MAX(a, b) ((a) > (b) ? (a) : (b))

#if defined(__GNUC__) || defined(__clang__)
#define PA_NORETURN __attribute__((noreturn))
#define PA_PRINTF(f, a) __attribute__((format(printf, f, a)))
#else
#define PA_NORETURN
#define PA_PRINTF(f, a)
#endif

/* ---- Alokacja (przerywa program przy braku pamięci) ---- */
void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t size);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
void die(const char *fmt, ...) PA_NORETURN PA_PRINTF(1, 2);
void pa_warn(const char *fmt, ...) PA_PRINTF(1, 2);

/* Dynamiczna tablica: VEC(int) v = {0}; VEC_PUSH(v, 5); */
#define VEC(T) struct { T *v; size_t n, cap; }
#define VEC_PUSH(vec, x)                                                     \
    do {                                                                     \
        if ((vec).n == (vec).cap) {                                          \
            (vec).cap = (vec).cap ? (vec).cap * 2 : 16;                      \
            (vec).v = xrealloc((vec).v, (vec).cap * sizeof(*(vec).v));       \
        }                                                                    \
        (vec).v[(vec).n++] = (x);                                            \
    } while (0)
#define VEC_FREE(vec) do { free((vec).v); (vec).v = NULL; (vec).n = (vec).cap = 0; } while (0)

/* ---- Adresy IP (IPv4 przechowywany w a[0..3], reszta wyzerowana) ---- */
typedef struct {
    uint8_t v;      /* 4 lub 6; 0 = brak adresu */
    uint8_t a[16];
} ipaddr_t;

int  ip_cmp(const ipaddr_t *x, const ipaddr_t *y);
int  ip_eq(const ipaddr_t *x, const ipaddr_t *y);
const char *ip_str(const ipaddr_t *ip);              /* bufor rotacyjny */
int  ip_parse(const char *s, ipaddr_t *out);         /* 0 = sukces */
int  ip_is_private(const ipaddr_t *ip);              /* RFC1918, ULA, link-local, loopback */
int  ip_is_multicast(const ipaddr_t *ip);            /* multicast lub broadcast */

uint64_t hash64(const void *data, size_t len, uint64_t seed);
uint64_t hash_mix(uint64_t x);

/* ---- Formatowanie (wyniki w buforach rotacyjnych - ważne do kolejnych ~48 wywołań) ---- */
const char *fmt_num(double v, int decimals);   /* "12 345,6" */
const char *fmt_int(uint64_t v);               /* "12 345" */
const char *fmt_bytes(double bytes);           /* "1,23 MB" (przedrostki dziesiętne) */
const char *fmt_bitrate(double bps);           /* "12,3 Mb/s" */
const char *fmt_compact(double v);             /* "12K", "3,4M" - do osi wykresów */
const char *fmt_dur(double sec);               /* "12,3 ms", "4 min 05 s" */
const char *fmt_pct(double frac, int decimals);/* frac=0.123 -> "12,3%" */
const char *fmt_utc(int64_t ns);               /* "2026-11-22 10:11:12.345 UTC" */
const char *fmt_port(int proto, uint16_t port);/* "443 (https)" */
const char *port_service(int proto, uint16_t port); /* NULL gdy nieznana */
int port_is_wellknown(int proto, uint16_t port);

int    cmp_double(const void *a, const void *b);
double quantile_sorted(const double *v, size_t n, double q);
double median_inplace(double *v, size_t n);    /* sortuje v */

#endif
