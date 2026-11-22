/*
 * Generator syntetycznych plików pcap do testów.
 *
 *   pcapgen normal plik.pcap   - sam zwykły ruch
 *   pcapgen mixed  plik.pcap   - zwykły ruch + scenariusze ataków
 *
 * Nie potrzebuje libpcap, zapisuje klasyczny pcap (Ethernet, mikrosekundy).
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *out;
static unsigned long npkts;
static uint64_t rng = 88172645463325252ULL;

static uint32_t rnd(void)
{
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return (uint32_t)(rng >> 16);
}

static void w32(uint32_t v) { fwrite(&v, 4, 1, out); }
static void w16(uint16_t v) { fwrite(&v, 2, 1, out); }

static void emit(double ts, const uint8_t *frame, uint32_t len)
{
    uint32_t sec = 1764000000u + (uint32_t)ts;
    uint32_t usec = (uint32_t)((ts - floor(ts)) * 1e6);
    w32(sec); w32(usec); w32(len); w32(len);
    fwrite(frame, 1, len, out);
    npkts++;
}

static uint16_t csum(const uint8_t *p, int n)
{
    uint32_t s = 0;
    for (int i = 0; i + 1 < n; i += 2) s += (uint32_t)(p[i] << 8 | p[i + 1]);
    if (n & 1) s += (uint32_t)p[n - 1] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

/* Adres v4 jako uint32 (a.b.c.d) */
#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

static int vlan_on;

/* Buduje ramkę Ethernet/IPv4 z nagłówkiem L4 (l4, l4len) i danymi o długości plen. */
static void ip4(double ts, uint32_t src, uint32_t dst, uint8_t proto, const uint8_t *l4, int l4len, int plen)
{
    uint8_t f[1600];
    memset(f, 0, sizeof f);
    int o = 12;
    memcpy(f, "\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01", 12);
    if (vlan_on) { f[o] = 0x81; f[o + 1] = 0; f[o + 2] = 0; f[o + 3] = 10; o += 4; }
    f[o] = 0x08; f[o + 1] = 0x00; o += 2;
    uint8_t *ip = f + o;
    int tot = 20 + l4len + plen;
    ip[0] = 0x45; ip[2] = (uint8_t)(tot >> 8); ip[3] = (uint8_t)tot;
    ip[8] = 64; ip[9] = proto;
    for (int i = 0; i < 4; i++) { ip[12 + i] = (uint8_t)(src >> (24 - 8 * i)); ip[16 + i] = (uint8_t)(dst >> (24 - 8 * i)); }
    uint16_t c = csum(ip, 20); ip[10] = (uint8_t)(c >> 8); ip[11] = (uint8_t)c;
    memcpy(ip + 20, l4, (size_t)l4len);
    for (int i = 0; i < plen; i++) ip[20 + l4len + i] = (uint8_t)('a' + i % 26);
    int len = o + tot;
    if (len < 60) len = 60;
    emit(ts, f, (uint32_t)len);
}

static void tcp4(double ts, uint32_t s, uint16_t sp, uint32_t d, uint16_t dp, uint32_t seq, uint32_t ack,
                 uint8_t flags, uint16_t win, int plen)
{
    uint8_t t[20] = {0};
    t[0] = (uint8_t)(sp >> 8); t[1] = (uint8_t)sp; t[2] = (uint8_t)(dp >> 8); t[3] = (uint8_t)dp;
    for (int i = 0; i < 4; i++) { t[4 + i] = (uint8_t)(seq >> (24 - 8 * i)); t[8 + i] = (uint8_t)(ack >> (24 - 8 * i)); }
    t[12] = 0x50; t[13] = flags; t[14] = (uint8_t)(win >> 8); t[15] = (uint8_t)win;
    ip4(ts, s, d, 6, t, 20, plen);
}

static void udp4(double ts, uint32_t s, uint16_t sp, uint32_t d, uint16_t dp, const uint8_t *pl, int plen)
{
    uint8_t u[8 + 512] = {0};
    u[0] = (uint8_t)(sp >> 8); u[1] = (uint8_t)sp; u[2] = (uint8_t)(dp >> 8); u[3] = (uint8_t)dp;
    u[4] = (uint8_t)((8 + plen) >> 8); u[5] = (uint8_t)(8 + plen);
    if (pl) { memcpy(u + 8, pl, (size_t)plen); ip4(ts, s, d, 17, u, 8 + plen, 0); }
    else ip4(ts, s, d, 17, u, 8, plen);
}

enum { F = 1, S = 2, R = 4, P = 8, A = 16, U = 32 };

/* Pełne połączenie TCP: uzgodnienie, n segmentów danych od serwera, zamknięcie FIN.
 * loss - prawdopodobieństwo retransmisji segmentu; zw - epizod zerowego okna. */
static double tcp_session(double t, uint32_t c, uint16_t cp, uint32_t s, uint16_t sp, int nseg,
                          double rtt, double loss, int zw)
{
    uint32_t cs = rnd(), ss = rnd();
    tcp4(t, c, cp, s, sp, cs, 0, S, 64240, 0);
    tcp4(t + rtt / 2, s, sp, c, cp, ss, cs + 1, S | A, 65160, 0);
    t += rtt;
    tcp4(t, c, cp, s, sp, cs + 1, ss + 1, A, 502, 0);
    tcp4(t + 0.0002, c, cp, s, sp, cs + 1, ss + 1, P | A, 502, 300);
    cs += 301;
    t += rtt / 2;
    uint32_t sq = ss + 1;
    for (int i = 0; i < nseg; i++) {
        tcp4(t, s, sp, c, cp, sq, cs, A, 509, 1400);
        if (loss > 0 && (rnd() % 1000) < loss * 1000) {
            tcp4(t + 0.2 + rtt, s, sp, c, cp, sq, cs, A, 509, 1400);   /* retransmisja po RTO */
        }
        sq += 1400;
        t += 0.004;
        if (i % 2 == 1) tcp4(t, c, cp, s, sp, cs, sq, A, (zw && i > nseg / 2 && i < nseg / 2 + 6) ? 0 : 1024, 0);
    }
    tcp4(t, s, sp, c, cp, sq, cs, F | A, 509, 0);
    tcp4(t + rtt / 2, c, cp, s, sp, cs, sq + 1, F | A, 1024, 0);
    tcp4(t + rtt, s, sp, c, cp, sq + 1, cs + 1, A, 509, 0);
    return t + rtt;
}

static int dns_msg(uint8_t *b, uint16_t id, int resp, int rcode, const char *name)
{
    memset(b, 0, 12);
    b[0] = (uint8_t)(id >> 8); b[1] = (uint8_t)id;
    b[2] = resp ? 0x81 : 0x01; b[3] = resp ? (uint8_t)(0x80 | rcode) : 0;
    b[5] = 1;
    int o = 12;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        int l = dot ? (int)(dot - p) : (int)strlen(p);
        b[o++] = (uint8_t)l;
        memcpy(b + o, p, (size_t)l);
        o += l;
        p += l + (dot ? 1 : 0);
    }
    b[o++] = 0;
    b[o++] = 0; b[o++] = 1; b[o++] = 0; b[o++] = 1;
    return o;
}

static void dns_pair(double t, uint32_t cli, uint32_t srv, const char *name, int rcode)
{
    uint8_t b[512];
    uint16_t id = (uint16_t)rnd(), sp = (uint16_t)(40000 + rnd() % 20000);
    int n = dns_msg(b, id, 0, 0, name);
    udp4(t, cli, sp, srv, 53, b, n);
    n = dns_msg(b, id, 1, rcode, name);
    udp4(t + 0.012, srv, 53, cli, sp, b, n);
}

static void background(double dur)
{
    static const char *names[] = {"www.example.com", "api.example.org", "cdn.example.net", "mail.example.com",
                                  "update.example.org"};
    for (double t = 0.5; t < dur; t += 0.7 + (rnd() % 100) / 100.0) {
        uint32_t c = IP(192, 168, 1, 10 + rnd() % 8);
        uint32_t s = IP(203, 0, 113, 10 + rnd() % 5);
        dns_pair(t, c, IP(192, 168, 1, 1), names[rnd() % 5], 0);
        tcp_session(t + 0.03, c, (uint16_t)(50000 + rnd() % 10000), s, rnd() % 4 ? 443 : 80,
                    5 + (int)(rnd() % 40), 0.02 + (rnd() % 30) / 1000.0, 0, 0);
        if (rnd() % 4 == 0) {
            uint8_t ntp[48] = {0x23};
            udp4(t + 0.1, c, 123, IP(198, 51, 100, 5), 123, ntp, 48);
            udp4(t + 0.13, IP(198, 51, 100, 5), 123, c, 123, ntp, 48);
        }
    }
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "użycie: pcapgen normal|mixed plik.pcap\n");
        return 2;
    }
    out = fopen(argv[2], "wb");
    if (!out) { perror(argv[2]); return 1; }
    w32(0xa1b2c3d4); w16(2); w16(4); w32(0); w32(0); w32(65535); w32(1);

    int mixed = strcmp(argv[1], "mixed") == 0;
    double dur = 60;
    if (!mixed) {
        background(dur);
        fclose(out);
        fprintf(stderr, "pcapgen: %lu pakietów\n", npkts);
        return 0;
    }

    /* każdy scenariusz dostaje osobne okno czasowe */
    background(15);
    double t = 15;
    /* skan portów TCP 1-1024: 10.0.0.66 -> 192.168.1.50 */
    uint32_t sc = IP(10, 0, 0, 66), tg = IP(192, 168, 1, 50);
    for (int p = 1; p <= 1024; p++, t += 0.001) {
        tcp4(t, sc, 61000, tg, (uint16_t)p, 1000 + (uint32_t)p, 0, S, 1024, 0);
        if (p == 22 || p == 80 || p == 443) {
            tcp4(t + 0.0003, tg, (uint16_t)p, sc, 61000, 5000, 1001 + (uint32_t)p, S | A, 29200, 0);
            tcp4(t + 0.0005, sc, 61000, tg, (uint16_t)p, 1001 + (uint32_t)p, 0, R, 0, 0);
        } else if (p < 1000) {
            tcp4(t + 0.0003, tg, (uint16_t)p, sc, 61000, 0, 1001 + (uint32_t)p, R | A, 0, 0);
        }
    }
    /* skan UDP 1-200 z ICMP port nieosiągalny */
    t = 18;
    for (int p = 1; p <= 200; p++, t += 0.002) {
        uint8_t z[4] = {0};
        udp4(t, sc, 61001, tg, (uint16_t)p, z, 4);
        uint8_t ic[8 + 28] = {3, 3};
        uint8_t *in = ic + 8;
        in[0] = 0x45; in[3] = 32; in[9] = 17;
        in[12] = 10; in[13] = 0; in[14] = 0; in[15] = 66; in[16] = 192; in[17] = 168; in[18] = 1; in[19] = 50;
        in[20] = 0xee; in[21] = 0x49; in[22] = (uint8_t)(p >> 8); in[23] = (uint8_t)p;
        ip4(t + 0.0004, tg, sc, 1, ic, 36, 0);
    }
    background(0);
    /* ruch typowy w tle przez cały czas */
    {
        double save = 0;
        (void)save;
    }
    /* SYN flood: 3000 SYN z losowych adresów na 192.168.1.80:80 */
    t = 25;
    uint32_t victim = IP(192, 168, 1, 80);
    for (int i = 0; i < 3000; i++, t += 0.0005) {
        uint32_t src = IP(100 + rnd() % 100, rnd() % 256, rnd() % 256, 1 + rnd() % 250);
        tcp4(t, src, (uint16_t)(1024 + rnd() % 60000), victim, 80, rnd(), 0, S, 512, 0);
        if (i % 3 == 0) tcp4(t + 0.0001, victim, 80, src, (uint16_t)(1024 + rnd() % 60000), rnd(), rnd(), S | A, 29200, 0);
    }
    /* zalew UDP: 6000 datagramów w 2 s */
    t = 32;
    for (int i = 0; i < 6000; i++, t += 2.0 / 6000) udp4(t, IP(10, 0, 0, 99), 4444, IP(192, 168, 1, 90), 9999, NULL, 512);
    /* skan XMAS/NULL/FIN */
    t = 36;
    for (int p = 1; p <= 30; p++, t += 0.01) {
        tcp4(t, IP(10, 0, 0, 77), 40000, IP(192, 168, 1, 51), (uint16_t)p, 1, 0, F | P | U, 1024, 0);
        tcp4(t + 0.003, IP(10, 0, 0, 77), 40001, IP(192, 168, 1, 51), (uint16_t)p, 1, 0, 0, 1024, 0);
        tcp4(t + 0.006, IP(10, 0, 0, 77), 40002, IP(192, 168, 1, 51), (uint16_t)p, 1, 0, F, 1024, 0);
    }
    /* tunelowanie DNS i DGA */
    t = 38;
    const char *b32 = "abcdefghijklmnopqrstuvwxyz234567";
    for (int i = 0; i < 40; i++, t += 0.05) {
        char name[160], lab[60];
        for (int k = 0; k < 52; k++) lab[k] = b32[rnd() % 32];
        lab[52] = 0;
        snprintf(name, sizeof name, "%s.t.tunnel-example.net", lab);
        dns_pair(t, IP(192, 168, 1, 15), IP(192, 168, 1, 1), name, 0);
    }
    for (int i = 0; i < 30; i++, t += 0.05) {
        char name[64];
        for (int k = 0; k < 14; k++) name[k] = (char)('a' + rnd() % 26);
        strcpy(name + 14, ".com");
        dns_pair(t, IP(192, 168, 1, 16), IP(192, 168, 1, 1), name, 3);
    }
    /* transfer ze stratami (retransmisje) i zerowym oknem, VLAN */
    vlan_on = 1;
    t = tcp_session(42, IP(192, 168, 1, 20), 51515, IP(203, 0, 113, 50), 443, 600, 0.03, 0.10, 1);
    vlan_on = 0;
    /* sesja telnet */
    tcp_session(50, IP(192, 168, 1, 21), 52000, IP(192, 168, 1, 2), 23, 6, 0.002, 0, 0);
    /* uszkodzone pakiety: IHL < 5 */
    uint8_t bad[60] = {0};
    memcpy(bad + 12, "\x08\x00\x43", 3);
    emit(55, bad, 60);
    emit(55.1, bad, 20);   /* zbyt krótka ramka */

    fclose(out);
    fprintf(stderr, "pcapgen: %lu pakietów\n", npkts);
    return 0;
}
