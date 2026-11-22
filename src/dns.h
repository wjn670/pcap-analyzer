/* Parsujemy tylko nagłówek i pierwsze pytanie - do statystyk to wystarcza. */
#ifndef PA_DNS_H
#define PA_DNS_H

#include <stddef.h>
#include <stdint.h>

enum { DQ_A, DQ_AAAA, DQ_CNAME, DQ_MX, DQ_NS, DQ_PTR, DQ_TXT, DQ_SRV, DQ_SOA,
       DQ_HTTPS, DQ_ANY, DQ_OTHER, DQ_COUNT };

typedef struct {
    uint16_t id;
    int qr;              /* 0 = zapytanie, 1 = odpowiedź */
    int opcode, rcode;
    int qdcount, ancount;
    char qname[256];     /* pierwsza nazwa (małe litery) */
    int qtype;           /* numer typu */
    int name_len;        /* długość nazwy w znakach */
    int max_label;       /* najdłuższa etykieta */
    double entropy;      /* entropia Shannona najdłuższej etykiety [bit/znak] */
} dns_msg_t;

typedef struct {
    char    *name;
    uint64_t queries;
    uint64_t nxdomain;
    uint64_t hash;
    int32_t  next;
} dns_name_t;

typedef struct {
    uint64_t queries, responses, malformed;
    uint64_t rcode[16];
    uint64_t qtype[DQ_COUNT];
    uint64_t suspicious;          /* zapytania o podejrzanych nazwach */
    uint64_t max_name_len;
    dns_name_t *names;
    size_t nnames, cap;
    int32_t *buckets;
    size_t nbuckets;
    int names_overflow;           /* osiągnięto limit unikalnych nazw */
} dns_stats_t;

int  dns_parse(const uint8_t *d, uint32_t len, dns_msg_t *m);   /* 0 = sukces */
int  dns_is_suspicious(const dns_msg_t *m);
int  dns_qtype_class(int qtype);                                /* -> DQ_* */
const char *dns_qtype_name(int dq);
const char *dns_rcode_name(int rcode);

void dns_stats_init(dns_stats_t *s);
void dns_stats_free(dns_stats_t *s);
void dns_account(dns_stats_t *s, const dns_msg_t *m);

#endif
