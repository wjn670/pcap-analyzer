#include "util.h"

#include <arpa/inet.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

/* ---- Alokacja i komunikaty ---- */

void die(const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, PA_NAME ": błąd: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(EXIT_FAILURE);
}

void pa_warn(const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, PA_NAME ": ostrzeżenie: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) die("brak pamięci (%zu B)", n);
    return p;
}

void *xcalloc(size_t n, size_t size)
{
    void *p = calloc(n ? n : 1, size ? size : 1);
    if (!p) die("brak pamięci (%zu x %zu B)", n, size);
    return p;
}

void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) die("brak pamięci (%zu B)", n);
    return q;
}

char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *d = xmalloc(n);
    memcpy(d, s, n);
    return d;
}

/* ---- Bufory rotacyjne dla funkcji formatujących ---- */

#define RING_N   48
#define RING_LEN 96

static char *ring_next(void)
{
    static char ring[RING_N][RING_LEN];
    static unsigned idx;
    idx = (idx + 1) % RING_N;
    ring[idx][0] = '\0';
    return ring[idx];
}

/* ---- Adresy IP ---- */

int ip_cmp(const ipaddr_t *x, const ipaddr_t *y)
{
    if (x->v != y->v) return x->v < y->v ? -1 : 1;
    return memcmp(x->a, y->a, x->v == 4 ? 4 : 16);
}

int ip_eq(const ipaddr_t *x, const ipaddr_t *y)
{
    return x->v == y->v && memcmp(x->a, y->a, x->v == 4 ? 4 : 16) == 0;
}

const char *ip_str(const ipaddr_t *ip)
{
    char *buf = ring_next();
    if (ip->v == 4)
        inet_ntop(AF_INET, ip->a, buf, RING_LEN);
    else if (ip->v == 6)
        inet_ntop(AF_INET6, ip->a, buf, RING_LEN);
    else
        snprintf(buf, RING_LEN, "?");
    return buf;
}

int ip_parse(const char *s, ipaddr_t *out)
{
    memset(out, 0, sizeof *out);
    if (inet_pton(AF_INET, s, out->a) == 1) { out->v = 4; return 0; }
    if (inet_pton(AF_INET6, s, out->a) == 1) { out->v = 6; return 0; }
    return -1;
}

int ip_is_private(const ipaddr_t *ip)
{
    const uint8_t *a = ip->a;
    if (ip->v == 4) {
        return a[0] == 10 || a[0] == 127 ||
               (a[0] == 172 && (a[1] & 0xf0) == 16) ||
               (a[0] == 192 && a[1] == 168) ||
               (a[0] == 169 && a[1] == 254) ||
               (a[0] == 100 && (a[1] & 0xc0) == 64); /* CGNAT 100.64/10 */
    }
    if (ip->v == 6) {
        static const uint8_t lo[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        return (a[0] & 0xfe) == 0xfc ||                 /* fc00::/7 ULA */
               (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) || /* fe80::/10 */
               memcmp(a, lo, 16) == 0;
    }
    return 0;
}

int ip_is_multicast(const ipaddr_t *ip)
{
    if (ip->v == 4)
        return (ip->a[0] & 0xf0) == 0xe0 ||
               (ip->a[0] == 255 && ip->a[1] == 255 && ip->a[2] == 255 && ip->a[3] == 255);
    if (ip->v == 6) return ip->a[0] == 0xff;
    return 0;
}

/* ---- Haszowanie (FNV-1a + finalizator splitmix64) ---- */

uint64_t hash_mix(uint64_t x)
{
    x ^= x >> 30; x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27; x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

uint64_t hash64(const void *data, size_t len, uint64_t seed)
{
    const uint8_t *p = data;
    uint64_t h = 0xcbf29ce484222325ULL ^ seed;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 0x100000001b3ULL;
    }
    return hash_mix(h);
}

/* ---- Formatowanie liczb ---- */

/* Separator tysięcy: twarda spacja (nie łamie się w akapitach PDF). */
#define THSEP "\xC2\xA0"

const char *fmt_num(double v, int decimals)
{
    char *out = ring_next();
    char tmp[64];
    if (!isfinite(v)) { snprintf(out, RING_LEN, "-"); return out; }
    snprintf(tmp, sizeof tmp, "%.*f", decimals, fabs(v));
    /* zaokrąglenie mogło dać "-0" */
    int neg = v < 0 && strspn(tmp, "0.") != strlen(tmp);
    char *dot = strchr(tmp, '.');
    size_t intlen = dot ? (size_t)(dot - tmp) : strlen(tmp);
    size_t o = 0;
    if (neg) out[o++] = '-';
    for (size_t i = 0; i < intlen && o + 4 < RING_LEN; i++) {
        out[o++] = tmp[i];
        size_t left = intlen - i - 1;
        if (left > 0 && left % 3 == 0 && intlen > 4) {
            memcpy(out + o, THSEP, 2);
            o += 2;
        }
    }
    if (dot) {
        out[o++] = ',';
        for (const char *p = dot + 1; *p && o + 1 < RING_LEN; p++) out[o++] = *p;
    }
    out[o] = '\0';
    return out;
}

const char *fmt_int(uint64_t v)
{
    return fmt_num((double)v, 0);
}

/* Liczba z przedrostkiem SI: wybiera 0-2 miejsc po przecinku zależnie od wielkości. */
static const char *fmt_prefixed(double v, const char *const *units, int nunits, double base)
{
    char *out = ring_next();
    int u = 0;
    double a = fabs(v);
    while (a >= base && u < nunits - 1) { a /= base; v /= base; u++; }
    int dec = (u == 0) ? 0 : (a < 10 ? 2 : (a < 100 ? 1 : 0));
    snprintf(out, RING_LEN, "%s" THSEP "%s", fmt_num(v, dec), units[u]);
    return out;
}

const char *fmt_bytes(double bytes)
{
    static const char *const u[] = {"B", "kB", "MB", "GB", "TB", "PB"};
    return fmt_prefixed(bytes, u, 6, 1000.0);
}

const char *fmt_bitrate(double bps)
{
    static const char *const u[] = {"b/s", "kb/s", "Mb/s", "Gb/s", "Tb/s"};
    return fmt_prefixed(bps, u, 5, 1000.0);
}

const char *fmt_compact(double v)
{
    char *out = ring_next();
    double a = fabs(v);
    if (a < 1000) {
        double r = round(v);
        if (fabs(v - r) < 1e-9) snprintf(out, RING_LEN, "%s", fmt_num(v, 0));
        else snprintf(out, RING_LEN, "%s", fmt_num(v, a < 10 ? 2 : 1));
        return out;
    }
    static const char *const u[] = {"", "K", "M", "G", "T"};
    int i = 0;
    while (a >= 1000 && i < 4) { a /= 1000; v /= 1000; i++; }
    double r = round(v);
    snprintf(out, RING_LEN, "%s%s", fabs(v - r) < 1e-9 ? fmt_num(v, 0) : fmt_num(v, 1), u[i]);
    return out;
}

const char *fmt_dur(double s)
{
    char *out = ring_next();
    if (!isfinite(s) || s < 0) { snprintf(out, RING_LEN, "-"); return out; }
    if (s == 0) snprintf(out, RING_LEN, "0 s");
    else if (s < 1e-3) snprintf(out, RING_LEN, "%s" THSEP "µs", fmt_num(s * 1e6, s < 1e-5 ? 1 : 0));
    else if (s < 1.0) snprintf(out, RING_LEN, "%s" THSEP "ms", fmt_num(s * 1e3, s < 0.01 ? 2 : (s < 0.1 ? 1 : 0)));
    else if (s < 60.0) snprintf(out, RING_LEN, "%s" THSEP "s", fmt_num(s, s < 10 ? 2 : 1));
    else if (s < 3600.0) {
        long t = (long)llround(s);
        snprintf(out, RING_LEN, "%ld" THSEP "min %02ld" THSEP "s", t / 60, t % 60);
    } else if (s < 86400.0) {
        long t = (long)llround(s / 60.0);
        snprintf(out, RING_LEN, "%ld" THSEP "h %02ld" THSEP "min", t / 60, t % 60);
    } else {
        long t = (long)llround(s / 3600.0);
        snprintf(out, RING_LEN, "%ld" THSEP "d %ld" THSEP "h", t / 24, t % 24);
    }
    return out;
}

const char *fmt_pct(double frac, int decimals)
{
    char *out = ring_next();
    if (!isfinite(frac)) { snprintf(out, RING_LEN, "-"); return out; }
    snprintf(out, RING_LEN, "%s%%", fmt_num(frac * 100.0, decimals));
    return out;
}

const char *fmt_utc(int64_t ns)
{
    char *out = ring_next();
    time_t sec = (time_t)(ns / 1000000000LL);
    int ms = (int)((ns % 1000000000LL) / 1000000LL);
    if (ms < 0) { ms += 1000; sec -= 1; }
    struct tm tm;
    if (!gmtime_r(&sec, &tm)) { snprintf(out, RING_LEN, "?"); return out; }
    char tmp[40];
    strftime(tmp, sizeof tmp, "%Y-%m-%d %H:%M:%S", &tm);
    snprintf(out, RING_LEN, "%s.%03d UTC", tmp, ms);
    return out;
}

/* ---- Usługi sieciowe (najpopularniejsze porty IANA) ---- */

/* proto: 6 = TCP, 17 = UDP, 0 = oba */
static const struct { uint8_t proto; uint16_t port; const char *name; } SERVICES[] = {
    {6, 20, "ftp-data"}, {6, 21, "ftp"}, {6, 22, "ssh"}, {6, 23, "telnet"},
    {6, 25, "smtp"}, {0, 53, "dns"}, {17, 67, "dhcp"}, {17, 68, "dhcp"},
    {17, 69, "tftp"}, {6, 80, "http"}, {0, 88, "kerberos"}, {6, 110, "pop3"},
    {17, 123, "ntp"}, {6, 135, "msrpc"}, {17, 137, "netbios-ns"}, {17, 138, "netbios-dgm"},
    {6, 139, "netbios-ssn"}, {6, 143, "imap"}, {17, 161, "snmp"}, {17, 162, "snmptrap"},
    {6, 179, "bgp"}, {0, 389, "ldap"}, {6, 443, "https"}, {17, 443, "quic"},
    {6, 445, "smb"}, {6, 465, "smtps"}, {17, 500, "isakmp"}, {6, 512, "rexec"},
    {6, 513, "rlogin"}, {6, 514, "rsh"}, {17, 514, "syslog"}, {6, 587, "submission"},
    {6, 631, "ipp"}, {6, 636, "ldaps"}, {6, 853, "dns-tls"}, {6, 873, "rsync"},
    {6, 993, "imaps"}, {6, 995, "pop3s"}, {0, 1194, "openvpn"}, {6, 1433, "mssql"},
    {6, 1883, "mqtt"}, {17, 1900, "ssdp"}, {6, 2049, "nfs"}, {6, 3128, "squid"},
    {6, 3306, "mysql"}, {6, 3389, "rdp"}, {17, 3478, "stun"}, {17, 4500, "ipsec-nat"},
    {17, 4789, "vxlan"}, {0, 5060, "sip"}, {17, 5353, "mdns"}, {17, 5355, "llmnr"},
    {6, 5432, "postgres"}, {6, 5672, "amqp"}, {6, 5900, "vnc"}, {6, 6379, "redis"},
    {6, 6443, "k8s-api"}, {6, 6667, "irc"}, {6, 8080, "http-alt"}, {6, 8443, "https-alt"},
    {6, 8883, "mqtts"}, {6, 9092, "kafka"}, {6, 9200, "elastic"}, {6, 27017, "mongodb"},
    {17, 51820, "wireguard"},
};

const char *port_service(int proto, uint16_t port)
{
    for (size_t i = 0; i < ARRAY_LEN(SERVICES); i++)
        if (SERVICES[i].port == port && (SERVICES[i].proto == 0 || SERVICES[i].proto == proto))
            return SERVICES[i].name;
    return NULL;
}

int port_is_wellknown(int proto, uint16_t port)
{
    return port < 1024 || port_service(proto, port) != NULL;
}

const char *fmt_port(int proto, uint16_t port)
{
    char *out = ring_next();
    const char *s = port_service(proto, port);
    if (s) snprintf(out, RING_LEN, "%u (%s)", port, s);
    else snprintf(out, RING_LEN, "%u", port);
    return out;
}

/* ---- Statystyka ---- */

int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

double quantile_sorted(const double *v, size_t n, double q)
{
    if (n == 0) return NAN;
    if (q <= 0) return v[0];
    if (q >= 1) return v[n - 1];
    double pos = q * (double)(n - 1);
    size_t i = (size_t)pos;
    double f = pos - (double)i;
    if (i + 1 >= n) return v[n - 1];
    return v[i] * (1.0 - f) + v[i + 1] * f;
}

double median_inplace(double *v, size_t n)
{
    if (n == 0) return NAN;
    qsort(v, n, sizeof *v, cmp_double);
    return quantile_sorted(v, n, 0.5);
}
