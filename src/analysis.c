#include "analysis.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const double RTT_EDGES_MS[RTT_BINS + 1] = {0, 0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50,
                                           100, 200, 500, 1000, 2000, 1e30};

/* ---- Inicjalizacja i dobór przedziałów czasu ---- */

#define MAX_BINS 20000

static double nice_bin(double raw)
{
    static const double steps[] = {0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5,
                                   1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800,
                                   3600, 7200, 10800, 21600, 43200, 86400};
    for (size_t i = 0; i < ARRAY_LEN(steps); i++)
        if (steps[i] >= raw) return steps[i];
    return 86400.0 * ceil(raw / 86400.0);
}

void analysis_init(analysis_t *A, const config_t *cfg, input_file_t *files, int nfiles,
                   int64_t t0_ns, int64_t t1_ns)
{
    memset(A, 0, sizeof *A);
    A->cfg = cfg;
    A->files = files;
    A->nfiles = nfiles;
    A->t0_ns = t0_ns;
    A->t1_ns = t1_ns;
    A->duration = (double)(t1_ns - t0_ns) * 1e-9;
    if (A->duration < 0) A->duration = 0;

    timeseries_t *ts = &A->ts;
    double bin = cfg->bin_width > 0 ? cfg->bin_width : nice_bin(A->duration / 240.0);
    if (A->duration / bin > MAX_BINS) {
        double nb = nice_bin(A->duration / MAX_BINS);
        if (cfg->bin_width > 0)
            pa_warn("przedział %.6g s daje zbyt wiele punktów; użyto %.6g s", bin, nb);
        bin = nb;
    }
    ts->bin = bin;
    ts->n = (int)ceil(A->duration / bin);
    if (ts->n < 1) ts->n = 1;
    ts->last_w = A->duration - (ts->n - 1) * bin;
    if (ts->last_w <= 0) ts->last_w = bin;
    for (int c = 0; c < TS_NCAT; c++) {
        ts->bytes[c] = xcalloc((size_t)ts->n, sizeof(double));
        ts->pkts[c] = xcalloc((size_t)ts->n, sizeof(double));
    }
    ts->syn = xcalloc((size_t)ts->n, sizeof(double));
    ts->retrans = xcalloc((size_t)ts->n, sizeof(double));
    ts->rst = xcalloc((size_t)ts->n, sizeof(double));
    ts->failed = xcalloc((size_t)ts->n, sizeof(double));

    flowtable_init(&A->ft);
    dns_stats_init(&A->dns);
    A->nhbuckets = 1024;
    A->hbuckets = xmalloc(A->nhbuckets * sizeof *A->hbuckets);
    for (size_t i = 0; i < A->nhbuckets; i++) A->hbuckets[i] = -1;
    A->tcp_ports = xcalloc(65536, sizeof(port_stat_t));
    A->udp_ports = xcalloc(65536, sizeof(port_stat_t));
}

static int ts_bin(const analysis_t *A, double t)
{
    int b = (int)(t / A->ts.bin);
    if (b < 0) b = 0;
    if (b >= A->ts.n) b = A->ts.n - 1;
    return b;
}

/* ---- Tablica hostów ---- */

static uint64_t ip_hash(const ipaddr_t *ip)
{
    return hash64(ip->a, 16, ip->v);
}

host_t *host_find(analysis_t *A, const ipaddr_t *ip)
{
    uint64_t h = ip_hash(ip);
    for (int32_t i = A->hbuckets[h & (A->nhbuckets - 1)]; i >= 0; i = A->hosts[i].next)
        if (ip_eq(&A->hosts[i].ip, ip)) return &A->hosts[i];
    return NULL;
}

static int32_t host_index(analysis_t *A, const ipaddr_t *ip)
{
    uint64_t h = ip_hash(ip);
    for (int32_t i = A->hbuckets[h & (A->nhbuckets - 1)]; i >= 0; i = A->hosts[i].next)
        if (ip_eq(&A->hosts[i].ip, ip)) return i;

    if (A->nhosts * 4 >= A->nhbuckets * 3) {
        size_t nb = A->nhbuckets * 2;
        int32_t *b = xmalloc(nb * sizeof *b);
        for (size_t i = 0; i < nb; i++) b[i] = -1;
        for (size_t i = 0; i < A->nhosts; i++) {
            size_t k = ip_hash(&A->hosts[i].ip) & (nb - 1);
            A->hosts[i].next = b[k];
            b[k] = (int32_t)i;
        }
        free(A->hbuckets);
        A->hbuckets = b;
        A->nhbuckets = nb;
    }
    if (A->nhosts == A->hcap) {
        A->hcap = A->hcap ? A->hcap * 2 : 256;
        A->hosts = xrealloc(A->hosts, A->hcap * sizeof *A->hosts);
    }
    int32_t idx = (int32_t)A->nhosts++;
    host_t *e = &A->hosts[idx];
    memset(e, 0, sizeof *e);
    e->ip = *ip;
    size_t k = h & (A->nhbuckets - 1);
    e->next = A->hbuckets[k];
    A->hbuckets[k] = idx;
    return idx;
}

/* ---- Przetwarzanie pakietu ---- */

static int bad_flag_kind(uint8_t fl)
{
    fl &= 0x3f;                                   /* bez ECE/CWR */
    if (fl == 0) return BF_NULL;
    if ((fl & (TCPF_SYN | TCPF_FIN)) == (TCPF_SYN | TCPF_FIN)) return BF_SYNFIN;
    if ((fl & (TCPF_SYN | TCPF_RST)) == (TCPF_SYN | TCPF_RST)) return BF_SYNRST;
    if ((fl & (TCPF_FIN | TCPF_PSH | TCPF_URG)) == (TCPF_FIN | TCPF_PSH | TCPF_URG) && !(fl & TCPF_ACK))
        return BF_XMAS;
    if (fl == TCPF_FIN) return BF_FIN;
    return -1;
}

static void tcp_packet_stats(analysis_t *A, const packet_t *p, host_t *hs)
{
    global_t *g = &A->g;
    uint8_t fl = p->tcp_flags;
    g->tcp_pkts_l4++;
    for (int b = 0; b < 8; b++)
        if (fl & (1u << b)) g->tcp_flag[b]++;
    if ((fl & (TCPF_SYN | TCPF_ACK)) == TCPF_SYN) g->tcp_syn_only++;
    else if ((fl & (TCPF_SYN | TCPF_ACK)) == (TCPF_SYN | TCPF_ACK)) g->tcp_synack++;
    else if ((fl & 0x3f) == TCPF_ACK && p->payload_len == 0) g->tcp_pure_ack++;
    if (p->payload_len > 0) g->data_segs++;

    int bf = bad_flag_kind(fl);
    if (bf >= 0) {
        g->tcp_bad[bf]++;
        uint32_t prev = 0;
        for (int i = 0; i < BF_COUNT; i++) prev += hs->bad_flags[i];
        if (prev == 0) hs->bad_t0 = p->ts;
        hs->bad_t1 = p->ts;
        hs->bad_flags[bf]++;
    }
    if (fl & TCPF_RST) hs->rst_sent++;
    hs->tcp_tx++;
    if ((fl & TCPF_SYN) && p->sport == p->dport && ip_eq(&p->src, &p->dst)) g->land++;
}

static void icmp_packet_stats(analysis_t *A, const packet_t *p, host_t *hs)
{
    global_t *g = &A->g;
    if (!p->l4_ok) return;
    if (icmp_is_unreach(p)) {
        g->icmp_unreach++;
        hs->icmp_unreach_sent++;
        if (icmp_is_port_unreach(p)) g->icmp_port_unreach++;
        if (p->icmp_inner && (p->in_proto == IPP_TCP || p->in_proto == IPP_UDP)) {
            int32_t fi = flow_lookup(&A->ft, &p->in_src, p->in_sport, &p->in_dst, p->in_dport, p->in_proto);
            if (fi >= 0) A->ft.v[fi].icmp_unreach++;
        }
        return;
    }
    int echo = (p->proto == IPP_ICMP && (p->icmp_type == 0 || p->icmp_type == 8)) ||
               (p->proto == IPP_ICMPV6 && (p->icmp_type == 128 || p->icmp_type == 129));
    int ttl = (p->proto == IPP_ICMP && p->icmp_type == 11) ||
              (p->proto == IPP_ICMPV6 && p->icmp_type == 3);
    if (echo) g->icmp_echo++;
    else if (ttl) g->icmp_ttl++;
    else g->icmp_other++;
}

static void dns_packet(analysis_t *A, const packet_t *p, host_t *hs, host_t *hd)
{
    dns_msg_t m;
    if (dns_parse(p->payload, p->payload_caplen, &m) != 0) {
        A->dns.malformed++;
        return;
    }
    dns_account(&A->dns, &m);
    if (!m.qr && p->dport == 53) {
        hs->dns_q++;
        if (dns_is_suspicious(&m)) {
            if (hs->dns_susp == 0) hs->dns_t0 = p->ts;
            hs->dns_t1 = p->ts;
            hs->dns_susp++;
            if (!hs->dns_example[0]) snprintf(hs->dns_example, sizeof hs->dns_example, "%s", m.qname);
        }
    } else if (m.qr && p->sport == 53) {
        hd->dns_resp_rx++;
        if (m.rcode == 3) hd->dns_nx_rx++;
    }
}

void analysis_packet(void *ctx, int file_idx, int dlt, int64_t ts_ns,
                     uint32_t caplen, uint32_t wirelen, const uint8_t *data)
{
    (void)file_idx;
    analysis_t *A = ctx;
    global_t *g = &A->g;
    packet_t p;
    double ts = (double)(ts_ns - A->t0_ns) * 1e-9;
    decode_packet(dlt, data, caplen, wirelen, ts, &p);

    g->pkts++;
    g->bytes += wirelen;
    if (p.vlan_tags) g->vlan++;
    int bin = ts_bin(A, ts);
    int cat = TS_OTHER;

    switch (p.status) {
    case DEC_TRUNC: g->trunc++; break;
    case DEC_MALFORMED: g->malformed++; break;
    case DEC_UNSUPPORTED: g->unsupported++; break;
    case DEC_NONIP:
        g->nonip++;
        if (p.ethertype == 0x0806) g->arp++;
        break;
    default: break;
    }

    if (p.status == DEC_OK) {
        if (p.ipv == 4) g->ipv4++;
        else g->ipv6++;
        if (p.fragment) g->fragments++;
        if (p.l4_trunc) g->l4_trunc++;
        if (p.l4_bad) g->l4_bad++;

        int pr = p.proto == IPP_TCP ? PR_TCP
               : p.proto == IPP_UDP ? PR_UDP
               : (p.proto == IPP_ICMP || p.proto == IPP_ICMPV6) ? PR_ICMP : PR_OTHER;
        g->ip_pkts[pr]++;
        g->ip_bytes[pr] += wirelen;
        cat = pr == PR_TCP ? TS_TCP : pr == PR_UDP ? TS_UDP : TS_OTHER;

        /* indeksy, bo dodanie drugiego hosta może przenieść tablicę */
        int32_t si = host_index(A, &p.src);
        int32_t di = host_index(A, &p.dst);
        host_t *hs = &A->hosts[si], *hd = &A->hosts[di];
        hs->tx_bytes += wirelen;
        hs->tx_pkts++;
        hd->rx_bytes += wirelen;
        hd->rx_pkts++;
        if (pr == PR_TCP) { hs->tcp_bytes += wirelen; hd->tcp_bytes += wirelen; }
        if (pr == PR_UDP) { hs->udp_bytes += wirelen; hd->udp_bytes += wirelen; }

        if (pr == PR_TCP || pr == PR_UDP) {
            uint32_t sb = wirelen / SIZE_STEP;
            if (sb >= SIZE_BINS) sb = SIZE_BINS - 1;
            g->size_hist[pr == PR_TCP ? 0 : 1][sb]++;
        }
        if (pr == PR_TCP && p.l4_ok) tcp_packet_stats(A, &p, hs);
        if (pr == PR_ICMP) icmp_packet_stats(A, &p, hs);

        int32_t fi;
        int dir;
        int ev = flow_update(&A->ft, &p, A->cfg->flow_timeout, &fi, &dir);
        if (ev & FEV_SYN) A->ts.syn[bin]++;
        if (ev & FEV_RST) A->ts.rst[bin]++;
        if (ev & FEV_RETRANS) { A->ts.retrans[bin]++; g->retrans++; }
        if (ev & FEV_OOO) g->ooo++;
        if (ev & FEV_LOST) g->lost++;
        if (ev & FEV_DUPACK) g->dupack++;
        if (ev & FEV_ZEROWIN) g->zerowin++;
        if (ev & FEV_KEEPALIVE) g->keepalive++;

        if (pr == PR_UDP && p.l4_ok && (p.sport == 53 || p.dport == 53) && p.payload_caplen >= 12)
            dns_packet(A, &p, hs, hd);
    }
    A->ts.bytes[cat][bin] += wirelen;
    A->ts.pkts[cat][bin] += 1;
}

/* ---- Wyniki pochodne ---- */

static const analysis_t *g_sort;   /* kontekst dla qsort (brak przenośnego qsort_r) */

static int cmp_host_bytes(const void *a, const void *b)
{
    const host_t *x = &g_sort->hosts[*(const int32_t *)a], *y = &g_sort->hosts[*(const int32_t *)b];
    uint64_t bx = x->tx_bytes + x->rx_bytes, by = y->tx_bytes + y->rx_bytes;
    return (bx < by) - (bx > by);
}

static int cmp_flow_bytes(const void *a, const void *b)
{
    uint64_t bx = flow_bytes(&g_sort->ft.v[*(const int32_t *)a]);
    uint64_t by = flow_bytes(&g_sort->ft.v[*(const int32_t *)b]);
    return (bx < by) - (bx > by);
}

static const port_stat_t *g_ports;
static int cmp_port_bytes(const void *a, const void *b)
{
    uint64_t bx = g_ports[*(const uint16_t *)a].bytes, by = g_ports[*(const uint16_t *)b].bytes;
    if (bx != by) return (bx < by) - (bx > by);
    return (int)*(const uint16_t *)a - (int)*(const uint16_t *)b;
}

static int cmp_dns_names(const void *a, const void *b)
{
    const dns_name_t *x = &g_sort->dns.names[*(const int32_t *)a];
    const dns_name_t *y = &g_sort->dns.names[*(const int32_t *)b];
    uint64_t qx = x->queries + x->nxdomain, qy = y->queries + y->nxdomain;
    if (qx != qy) return (qx < qy) - (qx > qy);
    return strcmp(x->name, y->name);
}

static uint16_t *rank_ports(const port_stat_t *ports, size_t *n_out)
{
    size_t n = 0;
    for (int i = 0; i < 65536; i++)
        if (ports[i].flows) n++;
    uint16_t *r = xmalloc((n ? n : 1) * sizeof *r);
    n = 0;
    for (int i = 0; i < 65536; i++)
        if (ports[i].flows) r[n++] = (uint16_t)i;
    g_ports = ports;
    pa_qsort(r, n, sizeof *r, cmp_port_bytes);
    *n_out = n;
    return r;
}

void analysis_finish(analysis_t *A)
{
    flowtable_t *ft = &A->ft;
    flowtable_finish(ft);
    g_sort = A;

    size_t nf = ft->n;
    A->rtt = xmalloc((nf ? nf : 1) * sizeof(double));
    for (int k = 0; k < 2; k++) {
        A->fsize[k] = xmalloc((nf ? nf : 1) * sizeof(double));
        A->fdur[k] = xmalloc((nf ? nf : 1) * sizeof(double));
    }
    A->tcp_flow_rank = xmalloc((nf ? nf : 1) * sizeof(int32_t));
    A->udp_flow_rank = xmalloc((nf ? nf : 1) * sizeof(int32_t));

    for (size_t i = 0; i < nf; i++) {
        const flow_t *f = &ft->v[i];
        int k = f->proto == IPP_TCP ? 0 : 1;
        port_stat_t *ps = k == 0 ? &A->tcp_ports[f->sport] : &A->udp_ports[f->sport];
        ps->pkts += flow_pkts(f);
        ps->bytes += flow_bytes(f);
        ps->flows++;

        host_t *hc = host_find(A, &f->cli), *hsrv = host_find(A, &f->srv);
        if (hc) hc->flows_out++;
        if (hsrv) hsrv->flows_in++;

        A->fsize[k][A->nfsize[k]++] = (double)flow_bytes(f);
        if (flow_pkts(f) >= 2) A->fdur[k][A->nfdur[k]++] = f->last - f->first;

        if (k == 0) {
            A->tcp_flows++;
            A->outcome[f->outcome]++;
            A->tcp_flow_rank[A->ntcp_flow_rank++] = (int32_t)i;
            if (tcp_outcome_failed(f->outcome)) {
                ps->failed++;
                A->ts.failed[ts_bin(A, f->first)]++;
            }
            if (f->rtt > 0) {
                A->rtt[A->nrtt++] = f->rtt;
                double ms = f->rtt * 1000.0;
                for (int b = 0; b < RTT_BINS; b++)
                    if (ms >= RTT_EDGES_MS[b] && ms < RTT_EDGES_MS[b + 1]) { A->rtt_hist[b]++; break; }
            }
        } else {
            A->udp_flows++;
            A->udp_flow_rank[A->nudp_flow_rank++] = (int32_t)i;
            if (f->d[1].pkts == 0) A->udp_oneway++;
        }
    }
    pa_qsort(A->rtt, A->nrtt, sizeof(double), cmp_double);
    for (int k = 0; k < 2; k++) {
        pa_qsort(A->fsize[k], A->nfsize[k], sizeof(double), cmp_double);
        pa_qsort(A->fdur[k], A->nfdur[k], sizeof(double), cmp_double);
    }
    pa_qsort(A->tcp_flow_rank, A->ntcp_flow_rank, sizeof(int32_t), cmp_flow_bytes);
    pa_qsort(A->udp_flow_rank, A->nudp_flow_rank, sizeof(int32_t), cmp_flow_bytes);

    A->host_rank = xmalloc((A->nhosts ? A->nhosts : 1) * sizeof(int32_t));
    for (size_t i = 0; i < A->nhosts; i++) A->host_rank[i] = (int32_t)i;
    A->nhost_rank = A->nhosts;
    pa_qsort(A->host_rank, A->nhost_rank, sizeof(int32_t), cmp_host_bytes);

    A->tcp_port_rank = rank_ports(A->tcp_ports, &A->ntcp_port_rank);
    A->udp_port_rank = rank_ports(A->udp_ports, &A->nudp_port_rank);

    A->dns_rank = xmalloc((A->dns.nnames ? A->dns.nnames : 1) * sizeof(int32_t));
    for (size_t i = 0; i < A->dns.nnames; i++) A->dns_rank[i] = (int32_t)i;
    A->ndns_rank = A->dns.nnames;
    pa_qsort(A->dns_rank, A->ndns_rank, sizeof(int32_t), cmp_dns_names);
}

void analysis_free(analysis_t *A)
{
    for (int c = 0; c < TS_NCAT; c++) {
        free(A->ts.bytes[c]);
        free(A->ts.pkts[c]);
    }
    free(A->ts.syn);
    free(A->ts.retrans);
    free(A->ts.rst);
    free(A->ts.failed);
    flowtable_free(&A->ft);
    dns_stats_free(&A->dns);
    free(A->hosts);
    free(A->hbuckets);
    free(A->tcp_ports);
    free(A->udp_ports);
    free(A->rtt);
    for (int k = 0; k < 2; k++) {
        free(A->fsize[k]);
        free(A->fdur[k]);
    }
    free(A->host_rank);
    free(A->tcp_port_rank);
    free(A->udp_port_rank);
    free(A->tcp_flow_rank);
    free(A->udp_flow_rank);
    free(A->dns_rank);
    VEC_FREE(A->an);
}
