/*
 * Wspólny stan analizy. Wypełnia go analysis.c, a moduły wyjściowe
 * (raport, wykresy, eksport) tylko z niego czytają.
 */
#ifndef PA_ANALYSIS_H
#define PA_ANALYSIS_H

#include "config.h"
#include "dns.h"
#include "flow.h"
#include "reader.h"
#include "util.h"

/* Kategorie ruchu w szeregach czasowych */
enum { TS_TCP = 0, TS_UDP, TS_OTHER, TS_NCAT };

/* Protokoły IP w statystykach globalnych */
enum { PR_TCP = 0, PR_UDP, PR_ICMP, PR_OTHER, PR_COUNT };

/* Nieprawidłowe kombinacje flag TCP */
enum { BF_NULL = 0, BF_FIN, BF_XMAS, BF_SYNFIN, BF_SYNRST, BF_COUNT };

/* Histogram rozmiarów pakietów: przedziały co 64 B, ostatni >= 1536 B */
#define SIZE_STEP  64
#define SIZE_BINS  25

/* Histogram RTT uzgadniania - granice przedziałów w ms */
#define RTT_BINS 15
extern const double RTT_EDGES_MS[RTT_BINS + 1];

typedef struct {
    uint64_t pkts, bytes;
    uint64_t ip_pkts[PR_COUNT], ip_bytes[PR_COUNT];
    uint64_t ipv4, ipv6, nonip, arp, trunc, malformed, unsupported;
    uint64_t fragments, vlan, l4_trunc, l4_bad;
    uint64_t tcp_pkts_l4;              /* segmenty TCP z pełnym nagłówkiem */
    uint64_t tcp_flag[8];              /* segmenty z daną flagą (bit 0 = FIN ...) */
    uint64_t tcp_syn_only, tcp_synack, tcp_pure_ack;
    uint64_t tcp_bad[BF_COUNT];
    uint64_t land;
    uint64_t icmp_unreach, icmp_port_unreach, icmp_echo, icmp_ttl, icmp_other;
    uint64_t size_hist[2][SIZE_BINS];  /* [0]=TCP, [1]=UDP */
    uint64_t retrans, ooo, lost, dupack, zerowin, keepalive, data_segs;
} global_t;

typedef struct {
    double  bin;                       /* szerokość przedziału [s] */
    int     n;                         /* liczba przedziałów */
    double  last_w;                    /* efektywna szerokość ostatniego przedziału */
    double *bytes[TS_NCAT];
    double *pkts[TS_NCAT];
    double *syn, *retrans, *rst, *failed;  /* zdarzenia TCP na przedział */
} timeseries_t;

typedef struct {
    ipaddr_t ip;
    uint64_t tx_bytes, rx_bytes, tx_pkts, rx_pkts;
    uint64_t tcp_bytes, udp_bytes;
    uint32_t flows_out, flows_in;      /* przepływy zainicjowane / przyjęte */
    uint32_t bad_flags[BF_COUNT];
    uint32_t rst_sent, tcp_tx;
    uint32_t icmp_unreach_sent;
    uint32_t dns_q, dns_susp, dns_nx_rx, dns_resp_rx;
    double   bad_t0, bad_t1;           /* czas pierwszego/ostatniego pakietu z błędnymi flagami */
    double   dns_t0, dns_t1;           /* czas pierwszego/ostatniego podejrzanego zapytania */
    char     dns_example[72];          /* przykładowa podejrzana nazwa */
    int32_t  next;
} host_t;

typedef struct {
    uint64_t pkts, bytes, flows, failed;
} port_stat_t;

/* Poziom ważności nieprawidłowości */
enum { SEV_LOW = 0, SEV_MEDIUM, SEV_HIGH, SEV_COUNT };

/* Rodzaje nieprawidłowości */
enum {
    AN_PORT_SCAN = 0, AN_HOST_SWEEP, AN_UDP_SCAN, AN_SYN_FLOOD, AN_UDP_FLOOD,
    AN_SPIKE, AN_BAD_FLAGS, AN_LAND, AN_RETRANS, AN_RETRANS_FLOW, AN_RST,
    AN_ZERO_WINDOW, AN_FAILED_CONN, AN_DNS_TUNNEL, AN_DNS_NXDOMAIN,
    AN_ICMP_UNREACH, AN_MALFORMED, AN_CLEARTEXT, AN_COUNT
};

typedef struct {
    int      type;                     /* AN_* */
    int      sev;                      /* SEV_* */
    double   t0, t1;                   /* przedział czasu [s od początku], t0<0 = brak */
    ipaddr_t src, dst;                 /* v=0 gdy nie dotyczy */
    double   score;                    /* do sortowania w obrębie poziomu */
    char     title[128];
    char     detail[768];
} anomaly_t;

typedef struct analysis {
    const config_t *cfg;
    input_file_t   *files;
    int             nfiles;

    int64_t t0_ns, t1_ns;              /* zakres czasu całej analizy */
    double  duration;                  /* [s] */

    global_t     g;
    timeseries_t ts;
    flowtable_t  ft;
    dns_stats_t  dns;

    host_t  *hosts;
    size_t   nhosts, hcap;
    int32_t *hbuckets;
    size_t   nhbuckets;

    port_stat_t *tcp_ports, *udp_ports;   /* [65536], wg portu usługi */

    /* --- wyniki pochodne (analysis_finish) --- */
    uint64_t tcp_flows, udp_flows;
    uint64_t outcome[TO_COUNT];
    uint64_t rtt_hist[RTT_BINS];
    double  *rtt;     size_t nrtt;        /* posortowane RTT [s] */
    double  *fsize[2]; size_t nfsize[2];  /* rozmiary przepływów TCP/UDP [B], posortowane */
    double  *fdur[2];  size_t nfdur[2];   /* czasy trwania (przepływy >= 2 pakietów) */
    uint64_t udp_oneway;                  /* przepływy UDP bez odpowiedzi */
    int32_t *host_rank;  size_t nhost_rank;   /* hosty wg bajtów malejąco */
    uint16_t *tcp_port_rank; size_t ntcp_port_rank;
    uint16_t *udp_port_rank; size_t nudp_port_rank;
    int32_t *tcp_flow_rank; size_t ntcp_flow_rank;
    int32_t *udp_flow_rank; size_t nudp_flow_rank;
    int32_t *dns_rank;  size_t ndns_rank;

    VEC(anomaly_t) an;
    int sev_count[SEV_COUNT];
} analysis_t;

void analysis_init(analysis_t *A, const config_t *cfg, input_file_t *files, int nfiles,
                   int64_t t0_ns, int64_t t1_ns);
void analysis_packet(void *ctx, int file_idx, int dlt, int64_t ts_ns,
                     uint32_t caplen, uint32_t wirelen, const uint8_t *data);
void analysis_finish(analysis_t *A);
void analysis_free(analysis_t *A);

host_t *host_find(analysis_t *A, const ipaddr_t *ip);   /* NULL gdy brak */

/* anomaly.c */
void anomaly_detect(analysis_t *A);
const char *anomaly_type_name(int type);   /* nazwa polska */
const char *anomaly_type_code(int type);   /* kod ASCII do CSV */
const char *sev_name(int sev);

#endif
