#include "dns.h"
#include "util.h"

#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NAMES 200000

static double label_entropy(const char *s, int n)
{
    if (n <= 0) return 0;
    int cnt[256] = {0};
    for (int i = 0; i < n; i++) cnt[(unsigned char)s[i]]++;
    double h = 0;
    for (int i = 0; i < 256; i++) {
        if (!cnt[i]) continue;
        double p = (double)cnt[i] / n;
        h -= p * log2(p);
    }
    return h;
}

int dns_parse(const uint8_t *d, uint32_t len, dns_msg_t *m)
{
    memset(m, 0, sizeof *m);
    if (len < 12) return -1;
    m->id = (uint16_t)((d[0] << 8) | d[1]);
    m->qr = d[2] >> 7;
    m->opcode = (d[2] >> 3) & 0x0f;
    m->rcode = d[3] & 0x0f;
    m->qdcount = (d[4] << 8) | d[5];
    m->ancount = (d[6] << 8) | d[7];
    if (m->opcode > 6) return -1;
    if (m->qdcount == 0) return m->qr ? 0 : -1;   /* zapytanie bez pytania - błędne */
    if (m->qdcount > 16) return -1;

    /* pierwsza nazwa w sekcji pytań (bez wskaźników kompresji) */
    uint32_t off = 12;
    int o = 0;
    int best_start = 0, best_len = 0;
    for (int labels = 0; ; labels++) {
        if (off >= len || labels > 127) return -1;
        uint8_t l = d[off++];
        if (l == 0) break;
        if ((l & 0xc0) != 0) return -1;
        if (off + l > len) return -1;
        if (o + l + 2 >= (int)sizeof m->qname) return -1;
        if (o > 0) m->qname[o++] = '.';
        int start = o;
        for (int i = 0; i < l; i++) {
            unsigned char c = d[off + (uint32_t)i];
            m->qname[o++] = (char)((c >= 0x21 && c < 0x7f) ? tolower(c) : '?');
        }
        if (l > best_len) { best_len = l; best_start = start; }
        off += l;
    }
    m->qname[o] = '\0';
    if (o == 0) { m->qname[0] = '.'; m->qname[1] = '\0'; }
    if (off + 4 > len) return -1;
    m->qtype = (d[off] << 8) | d[off + 1];
    m->name_len = o;
    m->max_label = best_len;
    m->entropy = label_entropy(m->qname + best_start, best_len);
    return 0;
}

/*
 * Heurystyka tunelowania: długa etykieta o wysokiej entropii (dane
 * zakodowane base32/base64/hex) albo bardzo długa nazwa. Typowe nazwy
 * hostów (CDN, chmury) mają etykiety krótsze niż 30 znaków.
 */
int dns_is_suspicious(const dns_msg_t *m)
{
    if (m->max_label >= 30 && m->entropy >= 3.5) return 1;
    if (m->name_len >= 100) return 1;
    return 0;
}

int dns_qtype_class(int t)
{
    switch (t) {
    case 1: return DQ_A;
    case 28: return DQ_AAAA;
    case 5: return DQ_CNAME;
    case 15: return DQ_MX;
    case 2: return DQ_NS;
    case 12: return DQ_PTR;
    case 16: return DQ_TXT;
    case 33: return DQ_SRV;
    case 6: return DQ_SOA;
    case 64: case 65: return DQ_HTTPS;
    case 255: return DQ_ANY;
    default: return DQ_OTHER;
    }
}

const char *dns_qtype_name(int dq)
{
    static const char *const n[DQ_COUNT] = {"A", "AAAA", "CNAME", "MX", "NS", "PTR",
                                            "TXT", "SRV", "SOA", "HTTPS/SVCB", "ANY", "inne"};
    return (dq >= 0 && dq < DQ_COUNT) ? n[dq] : "?";
}

const char *dns_rcode_name(int rc)
{
    switch (rc) {
    case 0: return "NOERROR";
    case 1: return "FORMERR";
    case 2: return "SERVFAIL";
    case 3: return "NXDOMAIN";
    case 4: return "NOTIMP";
    case 5: return "REFUSED";
    default: return "inny";
    }
}

void dns_stats_init(dns_stats_t *s)
{
    memset(s, 0, sizeof *s);
    s->nbuckets = 1024;
    s->buckets = xmalloc(s->nbuckets * sizeof *s->buckets);
    for (size_t i = 0; i < s->nbuckets; i++) s->buckets[i] = -1;
}

void dns_stats_free(dns_stats_t *s)
{
    for (size_t i = 0; i < s->nnames; i++) free(s->names[i].name);
    free(s->names);
    free(s->buckets);
    memset(s, 0, sizeof *s);
}

static dns_name_t *name_get(dns_stats_t *s, const char *name)
{
    uint64_t h = hash64(name, strlen(name), 0xd25);
    for (int32_t i = s->buckets[h & (s->nbuckets - 1)]; i >= 0; i = s->names[i].next)
        if (s->names[i].hash == h && strcmp(s->names[i].name, name) == 0) return &s->names[i];
    if (s->nnames >= MAX_NAMES) {
        s->names_overflow = 1;
        return NULL;
    }
    if (s->nnames * 4 >= s->nbuckets * 3) {       /* powiększenie tablicy */
        size_t nb = s->nbuckets * 2;
        int32_t *b = xmalloc(nb * sizeof *b);
        for (size_t i = 0; i < nb; i++) b[i] = -1;
        for (size_t i = 0; i < s->nnames; i++) {
            size_t k = s->names[i].hash & (nb - 1);
            s->names[i].next = b[k];
            b[k] = (int32_t)i;
        }
        free(s->buckets);
        s->buckets = b;
        s->nbuckets = nb;
    }
    if (s->nnames == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 256;
        s->names = xrealloc(s->names, s->cap * sizeof *s->names);
    }
    dns_name_t *e = &s->names[s->nnames];
    e->name = xstrdup(name);
    e->hash = h;
    e->queries = e->nxdomain = 0;
    size_t k = h & (s->nbuckets - 1);
    e->next = s->buckets[k];
    s->buckets[k] = (int32_t)s->nnames++;
    return e;
}

void dns_account(dns_stats_t *s, const dns_msg_t *m)
{
    if (!m->qr) {
        s->queries++;
        s->qtype[dns_qtype_class(m->qtype)]++;
        if (dns_is_suspicious(m)) s->suspicious++;
        if ((uint64_t)m->name_len > s->max_name_len) s->max_name_len = (uint64_t)m->name_len;
        dns_name_t *e = name_get(s, m->qname);
        if (e) e->queries++;
    } else {
        s->responses++;
        s->rcode[m->rcode & 0x0f]++;
        if (m->rcode == 3 && m->qname[0]) {
            dns_name_t *e = name_get(s, m->qname);
            if (e) e->nxdomain++;
        }
    }
}
