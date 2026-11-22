/*
 * Przepływ = dwukierunkowa wymiana o tej samej 5-krotce. Klienta ustalamy
 * po SYN, a jeśli go nie widać - po numerach portów.
 */
#ifndef PA_FLOW_H
#define PA_FLOW_H

#include "decode.h"
#include "util.h"

/* Końcowy stan połączenia TCP zaobserwowany w zrzucie */
enum tcp_outcome {
    TO_NONE = 0,       /* nie dotyczy (UDP) */
    TO_UNANSWERED,     /* SYN bez żadnej odpowiedzi */
    TO_REJECTED,       /* SYN odrzucony segmentem RST (port zamknięty) */
    TO_HALF_OPEN,      /* SYN + SYN/ACK, brak potwierdzenia klienta */
    TO_OPEN,           /* nawiązane, nie zakończone w czasie zrzutu */
    TO_CLOSED,         /* poprawnie zamknięte (FIN w obu kierunkach) */
    TO_HALF_CLOSED,    /* FIN tylko w jednym kierunku */
    TO_RESET,          /* nawiązane i przerwane segmentem RST */
    TO_MIDSTREAM,      /* rozpoczęte przed początkiem zrzutu */
    TO_COUNT
};

/* Zdarzenia zgłaszane dla pojedynczego pakietu (maska bitowa) */
enum {
    FEV_NEW_FLOW  = 0x001,
    FEV_SYN       = 0x002,   /* nowa próba połączenia */
    FEV_RETRANS   = 0x004,
    FEV_OOO       = 0x008,   /* segment poza kolejnością */
    FEV_LOST      = 0x010,   /* luka w numeracji (segment nieprzechwycony/utracony) */
    FEV_DUPACK    = 0x020,
    FEV_ZEROWIN   = 0x040,
    FEV_RST       = 0x080,
    FEV_KEEPALIVE = 0x100
};

typedef struct {
    uint64_t pkts, bytes, payload;
    uint32_t data_segs;        /* segmenty z danymi */
    uint32_t retrans, ooo, lost, dupack, zerowin, keepalive;
    uint32_t syn, fin, rst;
    uint32_t max_end;          /* najwyższy zaobserwowany seq + długość */
    uint32_t last_ack;
    uint16_t last_win;
    uint16_t mss;
    int8_t   wscale;
    uint8_t  seq_init, ack_init, flags_or;
    double   last_ts;
} flow_dir_t;

typedef struct {
    ipaddr_t cli, srv;         /* inicjator i odpowiadający */
    uint16_t cport, sport;
    uint8_t  proto;
    uint8_t  outcome;          /* enum tcp_outcome */
    uint8_t  syn_seen, synack_seen, established, rejected;
    uint8_t  active;
    uint32_t icmp_unreach;     /* komunikaty ICMP "nieosiągalny" dotyczące przepływu */
    uint32_t isn;
    double   first, last;
    double   t_syn;
    double   rtt;              /* RTT uzgadniania SYN -> ACK [s], <0 = brak */
    flow_dir_t d[2];           /* 0: klient -> serwer, 1: serwer -> klient */
    int32_t  next;             /* łańcuch w tablicy haszującej */
} flow_t;

typedef struct {
    flow_t  *v;
    size_t   n, cap;
    int32_t *buckets;
    size_t   nbuckets;
    size_t   nactive;
} flowtable_t;

void flowtable_init(flowtable_t *ft);
void flowtable_free(flowtable_t *ft);

/* Przetwarza pakiet TCP/UDP; zwraca maskę FEV_*. *idx = indeks przepływu (lub -1). */
int  flow_update(flowtable_t *ft, const packet_t *p, double timeout, int32_t *idx, int *dir);

/* Wyszukuje aktywny przepływ dla 5-krotki (dowolny kierunek); -1 gdy brak. */
int32_t flow_lookup(const flowtable_t *ft, const ipaddr_t *a, uint16_t ap,
                    const ipaddr_t *b, uint16_t bp, uint8_t proto);

/* Kończy wszystkie aktywne przepływy (wywoływać po ostatnim pakiecie). */
void flowtable_finish(flowtable_t *ft);

const char *tcp_outcome_name(int o);
int  tcp_outcome_failed(int o);     /* połączenie nie zostało nawiązane */

static inline uint64_t flow_bytes(const flow_t *f) { return f->d[0].bytes + f->d[1].bytes; }
static inline uint64_t flow_pkts(const flow_t *f)  { return f->d[0].pkts + f->d[1].pkts; }

#endif
