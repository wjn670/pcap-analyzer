/* Kolory są stałe dla protokołu: TCP niebieski, UDP pomarańczowy, reszta morski. */
#include "figures.h"
#include "chart.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COL_TCP   C_SERIES[0]
#define COL_UDP   C_SERIES[1]
#define COL_OTHER C_SERIES[2]

static const struct { const char *file, *title; } INFO[FIG_COUNT] = {
    {"01_przeplywnosc.png", "Przepływność w czasie"},
    {"02_pakiety_na_sekunde.png", "Natężenie ruchu (pakiety na sekundę)"},
    {"03_protokoly.png", "Udział protokołów"},
    {"04_rozmiary_pakietow.png", "Rozkład rozmiarów ramek"},
    {"05_hosty.png", "Najaktywniejsze hosty"},
    {"06_uslugi_tcp.png", "Usługi TCP"},
    {"07_uslugi_udp.png", "Usługi UDP"},
    {"08_flagi_tcp.png", "Segmenty TCP według flag"},
    {"09_stany_tcp.png", "Stany połączeń TCP"},
    {"10_rtt.png", "Czas uzgadniania połączeń TCP"},
    {"11_wielkosc_przeplywow.png", "Rozkład wielkości przepływów"},
    {"12_czas_przeplywow.png", "Rozkład czasu trwania przepływów"},
    {"13_zdarzenia_tcp.png", "Zdarzenia TCP w czasie"},
    {"14_dns.png", "Najczęściej odpytywane nazwy DNS"},
    {"15_nieprawidlowosci.png", "Oś czasu wykrytych nieprawidłowości"},
};

const char *figure_file(int id) { return INFO[id].file; }
const char *figure_title(int id) { return INFO[id].title; }

static int gantt_count(const analysis_t *A)
{
    int n = 0;
    for (size_t i = 0; i < A->an.n; i++)
        if (A->an.v[i].t0 >= 0) n++;
    return n > 16 ? 16 : n;
}

static int top_n(const analysis_t *A, size_t avail)
{
    int n = A->cfg->top_n;
    if ((size_t)n > avail) n = (int)avail;
    if (n > 20) n = 20;
    return n;
}

static int nonzero_outcomes(const analysis_t *A)
{
    int n = 0;
    for (int o = 1; o < TO_COUNT; o++)
        if (A->outcome[o]) n++;
    return n;
}

int figure_available(const analysis_t *A, int id)
{
    const global_t *g = &A->g;
    switch (id) {
    case FIG_THROUGHPUT:
    case FIG_PACKET_RATE:
    case FIG_PROTOCOLS: return g->pkts > 0;
    case FIG_SIZES: return g->ip_pkts[PR_TCP] + g->ip_pkts[PR_UDP] > 0;
    case FIG_TOP_HOSTS: return A->nhosts > 0;
    case FIG_TCP_PORTS: return A->ntcp_port_rank > 0;
    case FIG_UDP_PORTS: return A->nudp_port_rank > 0;
    case FIG_TCP_FLAGS: return g->tcp_pkts_l4 > 0;
    case FIG_TCP_STATES: return A->tcp_flows > 0;
    case FIG_RTT: return A->nrtt > 0;
    case FIG_FLOW_SIZE: return A->nfsize[0] + A->nfsize[1] > 0;
    case FIG_FLOW_DUR: return A->nfdur[0] + A->nfdur[1] > 0;
    case FIG_TCP_EVENTS: return A->tcp_flows > 0;
    case FIG_DNS: return A->ndns_rank > 0;
    case FIG_ANOMALIES: return gantt_count(A) > 0;
    default: return 0;
    }
}

double figure_height(const analysis_t *A, int id)
{
    double h;
    switch (id) {
    case FIG_PROTOCOLS: return 230;
    case FIG_TOP_HOSTS:
    case FIG_TCP_PORTS:
    case FIG_UDP_PORTS:
    case FIG_DNS: {
        size_t avail = id == FIG_TOP_HOSTS ? A->nhost_rank : id == FIG_TCP_PORTS ? A->ntcp_port_rank
                     : id == FIG_UDP_PORTS ? A->nudp_port_rank : A->ndns_rank;
        h = 120 + 27.0 * top_n(A, avail);
        break;
    }
    case FIG_TCP_STATES: h = 110 + 30.0 * nonzero_outcomes(A); break;
    case FIG_ANOMALIES: h = 150 + 24.0 * gantt_count(A); break;
    default: return 360;
    }
    if (h < 220) h = 220;
    if (h > 600) h = 600;
    return h;
}

/* ------------------------------------------------------------------ */

static void fig_timeseries(const analysis_t *A, cairo_t *cr, double W, double H, int bytes)
{
    const timeseries_t *ts = &A->ts;
    int n = ts->n;
    double *x = xmalloc((size_t)n * sizeof *x);
    double *y[TS_NCAT];
    int has_other = 0;
    for (int c = 0; c < TS_NCAT; c++) y[c] = xmalloc((size_t)n * sizeof(double));
    for (int i = 0; i < n; i++) {
        double w = (i == n - 1) ? ts->last_w : ts->bin;
        x[i] = i * ts->bin + w / 2;
        for (int c = 0; c < TS_NCAT; c++) {
            y[c][i] = bytes ? ts->bytes[c][i] * 8.0 / w : ts->pkts[c][i] / w;
            if (c == TS_OTHER && y[c][i] > 0) has_other = 1;
        }
    }
    chart_spec_t s = {0};
    char sub[192];
    s.title = figure_title(bytes ? FIG_THROUGHPUT : FIG_PACKET_RATE);
    snprintf(sub, sizeof sub, "Średnia w przedziałach %s; łącznie %s, średnio %s",
             fmt_dur(ts->bin), bytes ? fmt_bytes((double)A->g.bytes) : fmt_int(A->g.pkts),
             bytes ? fmt_bitrate(A->duration > 0 ? A->g.bytes * 8.0 / A->duration : 0)
                   : fmt_num(A->duration > 0 ? A->g.pkts / A->duration : 0, 1));
    if (!bytes) strncat(sub, " pak./s", sizeof sub - strlen(sub) - 1);
    s.subtitle = sub;
    s.ylabel = bytes ? "bity na sekundę" : "pakiety na sekundę";
    s.nseries = has_other ? 3 : 2;
    s.names[0] = "TCP"; s.colors[0] = COL_TCP;
    s.names[1] = "UDP"; s.colors[1] = COL_UDP;
    s.names[2] = "inne (ICMP, inne IP, nie-IP)"; s.colors[2] = COL_OTHER;

    double bands[20];
    int nb = 0;
    for (size_t i = 0; i < A->an.n && nb < 10; i++)
        if (A->an.v[i].type == AN_SPIKE) {
            bands[2 * nb] = A->an.v[i].t0;
            bands[2 * nb + 1] = A->an.v[i].t1;
            nb++;
        }
    const double *yy[3] = {y[TS_TCP], y[TS_UDP], y[TS_OTHER]};
    chart_lines(cr, W, H, &s, x, yy, n, A->duration, bytes ? VF_BITRATE : VF_NUM, bands, nb);
    for (int c = 0; c < TS_NCAT; c++) free(y[c]);
    free(x);
}

static void fig_protocols(const analysis_t *A, cairo_t *cr, double W, double H)
{
    const global_t *g = &A->g;
    uint64_t ipp = 0, ipb = 0;
    for (int k = 0; k < PR_COUNT; k++) { ipp += g->ip_pkts[k]; ipb += g->ip_bytes[k]; }
    double pk[5] = {(double)g->ip_pkts[PR_TCP], (double)g->ip_pkts[PR_UDP], (double)g->ip_pkts[PR_ICMP],
                    (double)g->ip_pkts[PR_OTHER], (double)(g->pkts - ipp)};
    double by[5] = {(double)g->ip_bytes[PR_TCP], (double)g->ip_bytes[PR_UDP], (double)g->ip_bytes[PR_ICMP],
                    (double)g->ip_bytes[PR_OTHER], (double)(g->bytes - ipb)};
    static const char *const names[5] = {"TCP", "UDP", "ICMP/ICMPv6", "inne IP", "nie-IP"};
    chart_spec_t s = {0};
    s.title = figure_title(FIG_PROTOCOLS);
    s.subtitle = "Udział w liczbie pakietów i w liczbie bajtów";
    double pv[5], bv[5];
    int ns = 0;
    for (int k = 0; k < 5; k++) {
        if (pk[k] <= 0 && by[k] <= 0) continue;
        s.names[ns] = names[k];
        s.colors[ns] = C_SERIES[k];
        pv[ns] = pk[k];
        bv[ns] = by[k];
        ns++;
    }
    s.nseries = ns;
    const char *rows[2] = {"Pakiety", "Bajty"};
    const double *vals[2] = {pv, bv};
    chart_segbars(cr, W, H, &s, rows, vals, 2);
}

static void fig_sizes(const analysis_t *A, cairo_t *cr, double W, double H)
{
    const global_t *g = &A->g;
    static char lab[SIZE_BINS][16];
    const char *labels[SIZE_BINS];
    double v[2][SIZE_BINS];
    double tot[2] = {0, 0};
    for (int k = 0; k < 2; k++)
        for (int i = 0; i < SIZE_BINS; i++) tot[k] += (double)g->size_hist[k][i];
    for (int i = 0; i < SIZE_BINS; i++) {
        if (i == SIZE_BINS - 1) snprintf(lab[i], sizeof lab[i], "%d+", i * SIZE_STEP);
        else snprintf(lab[i], sizeof lab[i], "%d", i * SIZE_STEP);
        labels[i] = lab[i];
        for (int k = 0; k < 2; k++) v[k][i] = tot[k] > 0 ? g->size_hist[k][i] / tot[k] : 0;
    }
    chart_spec_t s = {0};
    s.title = figure_title(FIG_SIZES);
    s.subtitle = "Odsetek ramek danego protokołu w przedziałach co 64 B";
    s.xlabel = "Rozmiar ramki [B] (dolna granica przedziału)";
    s.ylabel = "odsetek ramek";
    const double *vals[2];
    int ns = 0;
    if (tot[0] > 0) { s.names[ns] = "TCP"; s.colors[ns] = COL_TCP; vals[ns++] = v[0]; }
    if (tot[1] > 0) { s.names[ns] = "UDP"; s.colors[ns] = COL_UDP; vals[ns++] = v[1]; }
    s.nseries = ns;
    chart_columns(cr, W, H, &s, labels, vals, SIZE_BINS, VF_PCT, 0);
}

static void fig_hosts(const analysis_t *A, cairo_t *cr, double W, double H)
{
    int n = top_n(A, A->nhost_rank);
    const char **labels = xmalloc((size_t)(n ? n : 1) * sizeof *labels);
    char (*lab)[64] = xmalloc((size_t)(n ? n : 1) * sizeof *lab);
    double *v[3];
    for (int k = 0; k < 3; k++) v[k] = xmalloc((size_t)(n ? n : 1) * sizeof(double));
    for (int i = 0; i < n; i++) {
        const host_t *h = &A->hosts[A->host_rank[i]];
        snprintf(lab[i], sizeof lab[i], "%s", ip_str(&h->ip));
        labels[i] = lab[i];
        double tot = (double)(h->tx_bytes + h->rx_bytes);
        v[0][i] = (double)h->tcp_bytes;
        v[1][i] = (double)h->udp_bytes;
        v[2][i] = tot - v[0][i] - v[1][i];
        if (v[2][i] < 0) v[2][i] = 0;
    }
    chart_spec_t s = {0};
    s.title = figure_title(FIG_TOP_HOSTS);
    s.subtitle = "Bajty wysłane i odebrane przez host, z podziałem na protokoły";
    s.nseries = 3;
    s.names[0] = "TCP"; s.colors[0] = COL_TCP;
    s.names[1] = "UDP"; s.colors[1] = COL_UDP;
    s.names[2] = "inne"; s.colors[2] = COL_OTHER;
    const double *vals[3] = {v[0], v[1], v[2]};
    chart_hbar(cr, W, H, &s, labels, vals, n, VF_BYTES);
    for (int k = 0; k < 3; k++) free(v[k]);
    free(lab);
    free(labels);
}

static void fig_ports(const analysis_t *A, cairo_t *cr, double W, double H, int tcp)
{
    const uint16_t *rank = tcp ? A->tcp_port_rank : A->udp_port_rank;
    const port_stat_t *ps = tcp ? A->tcp_ports : A->udp_ports;
    int n = top_n(A, tcp ? A->ntcp_port_rank : A->nudp_port_rank);
    const char **labels = xmalloc((size_t)(n ? n : 1) * sizeof *labels);
    double *v = xmalloc((size_t)(n ? n : 1) * sizeof *v);
    char (*lab)[48] = xmalloc((size_t)(n ? n : 1) * sizeof *lab);
    for (int i = 0; i < n; i++) {
        const port_stat_t *p = &ps[rank[i]];
        snprintf(lab[i], sizeof lab[i], "%s", fmt_port(tcp ? IPP_TCP : IPP_UDP, rank[i]));
        labels[i] = lab[i];
        v[i] = (double)p->bytes;
    }
    chart_spec_t s = {0};
    s.title = figure_title(tcp ? FIG_TCP_PORTS : FIG_UDP_PORTS);
    s.subtitle = "Bajty w przepływach według portu po stronie serwera";
    s.nseries = 1;
    s.names[0] = tcp ? "TCP" : "UDP";
    s.colors[0] = tcp ? COL_TCP : COL_UDP;
    const double *vals[1] = {v};
    chart_hbar(cr, W, H, &s, labels, vals, n, VF_BYTES);
    free(lab);
    free(v);
    free(labels);
}

static void fig_flags(const analysis_t *A, cairo_t *cr, double W, double H)
{
    const global_t *g = &A->g;
    const char *labels[9] = {"SYN", "SYN+ACK", "ACK (puste)", "PSH", "FIN", "RST", "URG", "ECE", "CWR"};
    double v[9] = {(double)g->tcp_syn_only, (double)g->tcp_synack, (double)g->tcp_pure_ack,
                   (double)g->tcp_flag[3], (double)g->tcp_flag[0], (double)g->tcp_flag[2],
                   (double)g->tcp_flag[5], (double)g->tcp_flag[6], (double)g->tcp_flag[7]};
    chart_spec_t s = {0};
    char sub[160];
    snprintf(sub, sizeof sub, "Liczba segmentów z daną flagą (łącznie %s segmentów TCP)",
             fmt_int(g->tcp_pkts_l4));
    s.title = figure_title(FIG_TCP_FLAGS);
    s.subtitle = sub;
    s.ylabel = "segmenty";
    s.nseries = 1;
    s.names[0] = "TCP";
    s.colors[0] = COL_TCP;
    const double *vals[1] = {v};
    chart_columns(cr, W, H, &s, labels, vals, 9, VF_NUM, 1);
}

static void fig_states(const analysis_t *A, cairo_t *cr, double W, double H)
{
    const char *labels[TO_COUNT];
    double v[TO_COUNT];
    int n = 0;
    for (int o = 1; o < TO_COUNT; o++) {
        if (!A->outcome[o]) continue;
        labels[n] = tcp_outcome_name(o);
        v[n++] = (double)A->outcome[o];
    }
    chart_spec_t s = {0};
    char sub[160];
    uint64_t failed = A->outcome[TO_UNANSWERED] + A->outcome[TO_REJECTED] + A->outcome[TO_HALF_OPEN];
    uint64_t attempts = A->tcp_flows - A->outcome[TO_MIDSTREAM];
    snprintf(sub, sizeof sub, "Liczba połączeń wg stanu końcowego; %s prób nawiązania, nieudanych %s",
             fmt_int(attempts), fmt_pct(attempts ? (double)failed / attempts : 0, 1));
    s.title = figure_title(FIG_TCP_STATES);
    s.subtitle = sub;
    s.nseries = 1;
    s.names[0] = "TCP";
    s.colors[0] = COL_TCP;
    const double *vals[1] = {v};
    chart_hbar(cr, W, H, &s, labels, vals, n, VF_NUM);
}

static void fig_rtt(const analysis_t *A, cairo_t *cr, double W, double H)
{
    static char lab[RTT_BINS][16];
    const char *labels[RTT_BINS];
    double v[RTT_BINS];
    for (int i = 0; i < RTT_BINS; i++) {
        double e = RTT_EDGES_MS[i];
        if (i == RTT_BINS - 1) snprintf(lab[i], sizeof lab[i], "%g+", e);
        else snprintf(lab[i], sizeof lab[i], "%g", e);
        for (char *c = lab[i]; *c; c++)
            if (*c == '.') *c = ',';
        labels[i] = lab[i];
        v[i] = (double)A->rtt_hist[i];
    }
    chart_spec_t s = {0};
    char sub[192];
    snprintf(sub, sizeof sub, "Od SYN do potwierdzenia klienta; %s połączeń, mediana %s, 95. percentyl %s",
             fmt_int(A->nrtt), fmt_dur(quantile_sorted(A->rtt, A->nrtt, 0.5)),
             fmt_dur(quantile_sorted(A->rtt, A->nrtt, 0.95)));
    s.title = figure_title(FIG_RTT);
    s.subtitle = sub;
    s.xlabel = "RTT [ms] (dolna granica przedziału)";
    s.ylabel = "połączenia";
    s.nseries = 1;
    s.names[0] = "TCP";
    s.colors[0] = COL_TCP;
    const double *vals[1] = {v};
    chart_columns(cr, W, H, &s, labels, vals, RTT_BINS, VF_NUM, 1);
}

static void fig_cdf(const analysis_t *A, cairo_t *cr, double W, double H, int dur)
{
    chart_spec_t s = {0};
    s.title = figure_title(dur ? FIG_FLOW_DUR : FIG_FLOW_SIZE);
    s.subtitle = dur ? "Dystrybuanta empiryczna; przepływy z co najmniej 2 pakietami"
                     : "Dystrybuanta empiryczna; bajty w obu kierunkach";
    s.xlabel = dur ? "Czas trwania (skala logarytmiczna)" : "Wielkość przepływu (skala logarytmiczna)";
    s.ylabel = "odsetek przepływów";
    const double *sorted[2];
    size_t counts[2];
    int ns = 0;
    for (int k = 0; k < 2; k++) {
        size_t c = dur ? A->nfdur[k] : A->nfsize[k];
        if (!c) continue;
        s.names[ns] = k == 0 ? "TCP" : "UDP";
        s.colors[ns] = k == 0 ? COL_TCP : COL_UDP;
        sorted[ns] = dur ? A->fdur[k] : A->fsize[k];
        counts[ns] = c;
        ns++;
    }
    s.nseries = ns;
    chart_cdf(cr, W, H, &s, sorted, counts, dur ? VF_DUR : VF_BYTES, dur ? 1e-6 : 40);
}

static void fig_tcp_events(const analysis_t *A, cairo_t *cr, double W, double H)
{
    const timeseries_t *ts = &A->ts;
    int n = ts->n;
    double *x = xmalloc((size_t)n * sizeof *x);
    double *y[4];
    const double *src[4] = {ts->syn, ts->failed, ts->retrans, ts->rst};
    for (int k = 0; k < 4; k++) y[k] = xmalloc((size_t)n * sizeof(double));
    for (int i = 0; i < n; i++) {
        double w = (i == n - 1) ? ts->last_w : ts->bin;
        x[i] = i * ts->bin + w / 2;
        for (int k = 0; k < 4; k++) y[k][i] = src[k][i] / w;
    }
    chart_spec_t s = {0};
    s.title = figure_title(FIG_TCP_EVENTS);
    s.subtitle = "Liczba zdarzeń na sekundę w kolejnych przedziałach czasu";
    s.ylabel = "zdarzenia na sekundę";
    s.nseries = 4;
    s.names[0] = "nowe połączenia (SYN)";
    s.names[1] = "nieudane połączenia";
    s.names[2] = "retransmisje";
    s.names[3] = "segmenty RST";
    for (int k = 0; k < 4; k++) s.colors[k] = C_SERIES[k];
    const double *yy[4] = {y[0], y[1], y[2], y[3]};
    chart_lines(cr, W, H, &s, x, yy, n, A->duration, VF_NUM, NULL, 0);
    for (int k = 0; k < 4; k++) free(y[k]);
    free(x);
}

static void fig_dns(const analysis_t *A, cairo_t *cr, double W, double H)
{
    int n = top_n(A, A->ndns_rank);
    const char **labels = xmalloc((size_t)(n ? n : 1) * sizeof *labels);
    double *v[2];
    v[0] = xmalloc((size_t)(n ? n : 1) * sizeof(double));
    v[1] = xmalloc((size_t)(n ? n : 1) * sizeof(double));
    int any_nx = 0;
    for (int i = 0; i < n; i++) {
        const dns_name_t *e = &A->dns.names[A->dns_rank[i]];
        labels[i] = e->name;
        v[0][i] = (double)e->queries;
        v[1][i] = (double)e->nxdomain;
        if (e->nxdomain) any_nx = 1;
    }
    chart_spec_t s = {0};
    char sub[160];
    snprintf(sub, sizeof sub, "Liczba zapytań o nazwę; łącznie %s zapytań, %s unikalnych nazw",
             fmt_int(A->dns.queries), fmt_int(A->dns.nnames));
    s.title = figure_title(FIG_DNS);
    s.subtitle = sub;
    s.nseries = any_nx ? 2 : 1;
    s.names[0] = "zapytania";
    s.colors[0] = C_SERIES[0];
    s.names[1] = "odpowiedzi NXDOMAIN";
    s.colors[1] = C_SERIES[1];
    const double *vals[2] = {v[0], v[1]};
    chart_hbar(cr, W, H, &s, labels, vals, n, VF_NUM);
    free(v[0]);
    free(v[1]);
    free(labels);
}

static void fig_anomalies(const analysis_t *A, cairo_t *cr, double W, double H)
{
    int n = gantt_count(A);
    gantt_item_t *it = xcalloc((size_t)(n ? n : 1), sizeof *it);
    int k = 0, skipped = 0;
    for (size_t i = 0; i < A->an.n; i++) {
        const anomaly_t *a = &A->an.v[i];
        if (a->t0 < 0) { skipped++; continue; }
        if (k >= n) { skipped++; continue; }
        snprintf(it[k].label, sizeof it[k].label, "%s", a->title);
        it[k].t0 = a->t0;
        it[k].t1 = a->t1 >= a->t0 ? a->t1 : a->t0;
        it[k].sev = a->sev;
        k++;
    }
    chart_spec_t s = {0};
    char sub[160];
    if (skipped)
        snprintf(sub, sizeof sub, "Przedziały czasu, w których wystąpiły zdarzenia (pominięto %d bez "
                                  "określonego czasu lub poza listą)", skipped);
    else
        snprintf(sub, sizeof sub, "Przedziały czasu, w których wystąpiły zdarzenia");
    s.title = figure_title(FIG_ANOMALIES);
    s.subtitle = sub;
    chart_gantt(cr, W, H, &s, it, k, A->duration);
    free(it);
}

void figure_draw(const analysis_t *A, int id, cairo_t *cr, double W, double H)
{
    if (!figure_available(A, id)) {
        chart_spec_t s = {0};
        s.title = figure_title(id);
        chart_empty(cr, W, H, &s, "Brak danych");
        return;
    }
    switch (id) {
    case FIG_THROUGHPUT: fig_timeseries(A, cr, W, H, 1); break;
    case FIG_PACKET_RATE: fig_timeseries(A, cr, W, H, 0); break;
    case FIG_PROTOCOLS: fig_protocols(A, cr, W, H); break;
    case FIG_SIZES: fig_sizes(A, cr, W, H); break;
    case FIG_TOP_HOSTS: fig_hosts(A, cr, W, H); break;
    case FIG_TCP_PORTS: fig_ports(A, cr, W, H, 1); break;
    case FIG_UDP_PORTS: fig_ports(A, cr, W, H, 0); break;
    case FIG_TCP_FLAGS: fig_flags(A, cr, W, H); break;
    case FIG_TCP_STATES: fig_states(A, cr, W, H); break;
    case FIG_RTT: fig_rtt(A, cr, W, H); break;
    case FIG_FLOW_SIZE: fig_cdf(A, cr, W, H, 0); break;
    case FIG_FLOW_DUR: fig_cdf(A, cr, W, H, 1); break;
    case FIG_TCP_EVENTS: fig_tcp_events(A, cr, W, H); break;
    case FIG_DNS: fig_dns(A, cr, W, H); break;
    case FIG_ANOMALIES: fig_anomalies(A, cr, W, H); break;
    default: break;
    }
}

int figures_write_png(const analysis_t *A, const char *dir)
{
    int written = 0;
    const double scale = 2.0;
    for (int id = 0; id < FIG_COUNT; id++) {
        if (!figure_available(A, id)) continue;
        double H = figure_height(A, id);
        cairo_surface_t *s = cairo_image_surface_create(CAIRO_FORMAT_RGB24, (int)(FIG_W * scale),
                                                        (int)(H * scale));
        cairo_t *cr = cairo_create(s);
        cairo_scale(cr, scale, scale);
        figure_draw(A, id, cr, FIG_W, H);
        cairo_destroy(cr);
        char path[4096];
        snprintf(path, sizeof path, "%s/%s", dir, figure_file(id));
        cairo_status_t st = cairo_surface_write_to_png(s, path);
        cairo_surface_destroy(s);
        if (st != CAIRO_STATUS_SUCCESS) {
            pa_warn("nie można zapisać %s: %s", path, cairo_status_to_string(st));
            return -1;
        }
        written++;
    }
    return written;
}
