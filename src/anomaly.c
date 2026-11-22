/*
 * Detektory działają na zagregowanych wynikach (przepływy, hosty, szeregi
 * czasowe), więc uruchamiamy je dopiero po przejściu wszystkich pakietów.
 * Progi są w config_t.
 */
#include "analysis.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Pomocnicze ---- */

static anomaly_t *add(analysis_t *A, int type, int sev, double t0, double t1, double score,
                      const char *title_fmt, ...) PA_PRINTF(7, 8);

static anomaly_t *add(analysis_t *A, int type, int sev, double t0, double t1, double score,
                      const char *title_fmt, ...)
{
    anomaly_t a;
    memset(&a, 0, sizeof a);
    a.type = type;
    a.sev = sev;
    a.t0 = t0;
    a.t1 = t1;
    a.score = score;
    va_list ap;
    va_start(ap, title_fmt);
    vsnprintf(a.title, sizeof a.title, title_fmt, ap);
    va_end(ap);
    VEC_PUSH(A->an, a);
    return &A->an.v[A->an.n - 1];
}

/* Dopisuje tekst do pola detail. */
static void det(anomaly_t *a, const char *fmt, ...) PA_PRINTF(2, 3);
static void det(anomaly_t *a, const char *fmt, ...)
{
    size_t len = strlen(a->detail);
    if (len + 1 >= sizeof a->detail) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(a->detail + len, sizeof a->detail - len, fmt, ap);
    va_end(ap);
}

/* Rekord próby połączenia używany przez detektory skanowania i zalewu. */
typedef struct {
    ipaddr_t a, b;          /* klient, serwer */
    uint16_t port;          /* port usługi */
    uint8_t  answered;      /* TCP: SYN/ACK; UDP: odpowiedź UDP */
    uint8_t  rejected;      /* TCP: RST; UDP: ICMP port nieosiągalny */
    uint8_t  outcome;
    double   t0, t1;
} rec_t;

static int cmp_ab_port(const void *x, const void *y)
{
    const rec_t *r = x, *s = y;
    int c = ip_cmp(&r->a, &s->a);
    if (c) return c;
    if ((c = ip_cmp(&r->b, &s->b))) return c;
    return (int)r->port - (int)s->port;
}

static int cmp_a_port_b(const void *x, const void *y)
{
    const rec_t *r = x, *s = y;
    int c = ip_cmp(&r->a, &s->a);
    if (c) return c;
    if (r->port != s->port) return (int)r->port - (int)s->port;
    return ip_cmp(&r->b, &s->b);
}

static int cmp_b_port_a(const void *x, const void *y)
{
    const rec_t *r = x, *s = y;
    int c = ip_cmp(&r->b, &s->b);
    if (c) return c;
    if (r->port != s->port) return (int)r->port - (int)s->port;
    return ip_cmp(&r->a, &s->a);
}

/* ---- Skanowanie pionowe (wiele portów jednego hosta) ---- */

static void detect_vertical(analysis_t *A, rec_t *r, size_t n, int proto)
{
    const config_t *cfg = A->cfg;
    qsort(r, n, sizeof *r, cmp_ab_port);
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && ip_eq(&r[j].a, &r[i].a) && ip_eq(&r[j].b, &r[i].b)) j++;

        /* liczenie unikalnych portów i najlepszego wyniku dla każdego z nich */
        int ports = 0, open = 0, closed = 0, silent = 0;
        double t0 = r[i].t0, t1 = r[i].t1;
        for (size_t k = i; k < j;) {
            size_t m = k;
            int ans = 0, rej = 0;
            while (m < j && r[m].port == r[k].port) {
                ans |= r[m].answered;
                rej |= r[m].rejected;
                if (r[m].t0 < t0) t0 = r[m].t0;
                if (r[m].t1 > t1) t1 = r[m].t1;
                m++;
            }
            ports++;
            if (ans) open++;
            else if (rej) closed++;
            else silent++;
            k = m;
        }

        if (ports >= cfg->scan_ports && (double)(closed + silent) / ports >= 0.5 &&
            !ip_is_multicast(&r[i].b)) {
            int sev = ports >= 100 ? SEV_HIGH : SEV_MEDIUM;
            const char *pname = proto == IPP_TCP ? "TCP" : "UDP";
            anomaly_t *a = add(A, proto == IPP_TCP ? AN_PORT_SCAN : AN_UDP_SCAN, sev, t0, t1, ports,
                               "Skanowanie %d portów %s hosta %s", ports, pname, ip_str(&r[i].b));
            a->src = r[i].a;
            a->dst = r[i].b;
            double span = t1 - t0;
            det(a, "Host %s wysłał próby połączeń %s do %d różnych portów hosta %s w ciągu %s",
                ip_str(&r[i].a), pname, ports, ip_str(&r[i].b), fmt_dur(span));
            if (span > 0) det(a, " (%s portów/s)", fmt_num(ports / span, 1));
            if (proto == IPP_TCP)
                det(a, ". Wynik: otwarte (SYN/ACK) %d, zamknięte (RST) %d, bez odpowiedzi %d.",
                    open, closed, silent);
            else
                det(a, ". Wynik: odpowiedź UDP %d, ICMP \"port nieosiągalny\" %d, brak odpowiedzi %d.",
                    open, closed, silent);
            if (open > 0) {
                det(a, " %s: ", proto == IPP_TCP ? "Otwarte porty" : "Porty, które odpowiedziały");
                int shown = 0;
                for (size_t k = i; k < j && shown < 12;) {
                    size_t m = k;
                    int ans = 0;
                    while (m < j && r[m].port == r[k].port) ans |= r[m++].answered;
                    if (ans) det(a, "%s%s", shown++ ? ", " : "", fmt_port(proto, r[k].port));
                    k = m;
                }
                if (open > shown) det(a, " i %d innych", open - shown);
                det(a, ".");
            }
        }
        i = j;
    }
}

/* ---- Skanowanie poziome (jeden port na wielu hostach) ---- */

static void detect_sweep(analysis_t *A, rec_t *r, size_t n)
{
    const config_t *cfg = A->cfg;
    qsort(r, n, sizeof *r, cmp_a_port_b);
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && ip_eq(&r[j].a, &r[i].a) && r[j].port == r[i].port) j++;
        int hosts = 0, answered = 0;
        double t0 = r[i].t0, t1 = r[i].t1;
        for (size_t k = i; k < j;) {
            size_t m = k;
            int ans = 0;
            while (m < j && ip_eq(&r[m].b, &r[k].b)) {
                ans |= r[m].answered;
                if (r[m].t0 < t0) t0 = r[m].t0;
                if (r[m].t1 > t1) t1 = r[m].t1;
                m++;
            }
            hosts++;
            answered += ans;
            k = m;
        }
        if (hosts >= cfg->scan_hosts && (double)(hosts - answered) / hosts >= 0.5) {
            int sev = hosts >= 100 ? SEV_HIGH : SEV_MEDIUM;
            anomaly_t *a = add(A, AN_HOST_SWEEP, sev, t0, t1, hosts,
                               "Przeszukiwanie %d hostów na porcie TCP %s", hosts,
                               fmt_port(IPP_TCP, r[i].port));
            a->src = r[i].a;
            det(a, "Host %s próbował połączyć się z portem %s na %d różnych hostach w ciągu %s; "
                   "odpowiedziało %d. Wzorzec typowy dla wyszukiwania podatnych usług w sieci.",
                ip_str(&r[i].a), fmt_port(IPP_TCP, r[i].port), hosts, fmt_dur(t1 - t0), answered);
            if (answered > 0) {
                det(a, " Odpowiedziały m.in.: ");
                int shown = 0;
                for (size_t k = i; k < j && shown < 6; k++)
                    if (r[k].answered && (k == i || !ip_eq(&r[k].b, &r[k - 1].b)))
                        det(a, "%s%s", shown++ ? ", " : "", ip_str(&r[k].b));
                det(a, ".");
            }
        }
        i = j;
    }
}

/* ---- SYN flood i powtarzające się nieudane połączenia ---- */

static void detect_synflood(analysis_t *A, rec_t *r, size_t n)
{
    const config_t *cfg = A->cfg;
    qsort(r, n, sizeof *r, cmp_b_port_a);
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && ip_eq(&r[j].b, &r[i].b) && r[j].port == r[i].port) j++;
        int attempts = (int)(j - i), failed = 0, clients = 0;
        int halfopen = 0, silent = 0, rejected = 0;
        double t0 = r[i].t0, t1 = r[i].t1;
        for (size_t k = i; k < j; k++) {
            if (tcp_outcome_failed(r[k].outcome)) failed++;
            if (r[k].outcome == TO_HALF_OPEN) halfopen++;
            else if (r[k].outcome == TO_UNANSWERED) silent++;
            else if (r[k].outcome == TO_REJECTED) rejected++;
            if (k == i || !ip_eq(&r[k].a, &r[k - 1].a)) clients++;
            if (r[k].t0 < t0) t0 = r[k].t0;
            if (r[k].t1 > t1) t1 = r[k].t1;
        }
        double span = t1 - t0;
        double rate = failed / (span > 1.0 ? span : 1.0);

        if (failed >= cfg->synflood_min && (double)failed / attempts >= 0.5) {
            int sev = SEV_HIGH;
            anomaly_t *a = add(A, AN_SYN_FLOOD, sev, t0, t1, failed,
                               "SYN flood na %s:%s", ip_str(&r[i].b), fmt_port(IPP_TCP, r[i].port));
            a->dst = r[i].b;
            if (clients == 1) a->src = r[i].a;
            det(a, "Do usługi %s:%s wysłano %d prób nawiązania połączenia (SYN) z %d różnych "
                   "adresów w ciągu %s (średnio %s nieudanych prób/s). Nieudane: %d "
                   "(półotwarte %d, bez odpowiedzi %d, odrzucone %d).",
                ip_str(&r[i].b), fmt_port(IPP_TCP, r[i].port), attempts, clients, fmt_dur(span),
                fmt_num(rate, 0), failed, halfopen, silent, rejected);
            if (clients >= 50)
                det(a, " Duża liczba adresów źródłowych wskazuje na ich fałszowanie (rozproszony atak DoS).");
            else
                det(a, " Źródło: %s%s.", ip_str(&r[i].a), clients > 1 ? " i inne" : "");
        } else if (failed >= 10 && clients <= 3 && (double)failed / attempts >= 0.8) {
            anomaly_t *a = add(A, AN_FAILED_CONN, SEV_LOW, t0, t1, failed,
                               "Nieudane połączenia z %s:%s", ip_str(&r[i].b),
                               fmt_port(IPP_TCP, r[i].port));
            a->src = r[i].a;
            a->dst = r[i].b;
            det(a, "%d z %d prób połączenia z usługą %s:%s od %d klient%s nie powiodło się "
                   "(bez odpowiedzi %d, odrzucone %d, półotwarte %d). Usługa może być "
                   "niedostępna lub blokowana przez zaporę.",
                failed, attempts, ip_str(&r[i].b), fmt_port(IPP_TCP, r[i].port), clients,
                clients == 1 ? "a" : "ów", silent, rejected, halfopen);
        }
        i = j;
    }
}

/* ---- Zalew UDP ---- */

typedef struct {
    ipaddr_t dst, src;
    uint64_t pkts, bytes, reply;
    double t0, t1;
} udpagg_t;

static int cmp_udpagg(const void *x, const void *y)
{
    const udpagg_t *r = x, *s = y;
    int c = ip_cmp(&r->dst, &s->dst);
    return c ? c : ip_cmp(&r->src, &s->src);
}

static void detect_udp_flood(analysis_t *A)
{
    const config_t *cfg = A->cfg;
    const flowtable_t *ft = &A->ft;
    udpagg_t *v = xmalloc((ft->n ? ft->n : 1) * sizeof *v);
    size_t n = 0;
    for (size_t i = 0; i < ft->n; i++) {
        const flow_t *f = &ft->v[i];
        if (f->proto != IPP_UDP || ip_is_multicast(&f->srv)) continue;
        udpagg_t *u = &v[n++];
        u->dst = f->srv;
        u->src = f->cli;
        u->pkts = f->d[0].pkts;
        u->bytes = f->d[0].bytes;
        u->reply = f->d[1].pkts;
        u->t0 = f->first;
        u->t1 = f->last;
    }
    qsort(v, n, sizeof *v, cmp_udpagg);
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        uint64_t pkts = 0, bytes = 0, reply = 0;
        int sources = 0;
        double t0 = v[i].t0, t1 = v[i].t1;
        while (j < n && ip_eq(&v[j].dst, &v[i].dst)) {
            pkts += v[j].pkts;
            bytes += v[j].bytes;
            reply += v[j].reply;
            if (j == i || !ip_eq(&v[j].src, &v[j - 1].src)) sources++;
            if (v[j].t0 < t0) t0 = v[j].t0;
            if (v[j].t1 > t1) t1 = v[j].t1;
            j++;
        }
        double span = t1 - t0;
        double rate = pkts / (span > 1.0 ? span : 1.0);
        if (rate >= cfg->udpflood_pps && pkts >= (uint64_t)(2 * cfg->udpflood_pps) &&
            reply < pkts / 10) {
            int sev = (sources >= 50 || rate >= 10 * cfg->udpflood_pps) ? SEV_HIGH : SEV_MEDIUM;
            anomaly_t *a = add(A, AN_UDP_FLOOD, sev, t0, t1, rate,
                               "Zalew UDP na %s", ip_str(&v[i].dst));
            a->dst = v[i].dst;
            if (sources == 1) a->src = v[i].src;
            det(a, "Host %s otrzymał %s datagramów UDP (%s) z %d adres%s w ciągu %s, czyli średnio "
                   "%s pak./s (%s), przy %s pakietach odpowiedzi. Ruch jednokierunkowy o takim "
                   "natężeniu jest typowy dla ataku wolumetrycznego DoS.",
                ip_str(&v[i].dst), fmt_int(pkts), fmt_bytes((double)bytes), sources,
                sources == 1 ? "u" : "ów", fmt_dur(span), fmt_num(rate, 0),
                fmt_bitrate(bytes * 8.0 / (span > 1.0 ? span : 1.0)), fmt_int(reply));
            if (sources == 1) det(a, " Źródło: %s.", ip_str(&v[i].src));
        }
        i = j;
    }
    free(v);
}

/* ---- Skoki natężenia ruchu (odporny z-score: mediana + k * 1,4826 * MAD) ---- */

typedef struct { double t0, t1, peak, pkts, cat[TS_NCAT]; } spike_t;

static int cmp_spike(const void *x, const void *y)
{
    double a = ((const spike_t *)x)->peak, b = ((const spike_t *)y)->peak;
    return (a < b) - (a > b);
}

static void detect_spikes(analysis_t *A)
{
    const timeseries_t *ts = &A->ts;
    int n = ts->n;
    if (n > 1 && ts->last_w < 0.5 * ts->bin) n--;   /* niepełny ostatni przedział */
    if (n < 20) return;

    double *rate = xmalloc((size_t)n * sizeof *rate);
    double *tmp = xmalloc((size_t)n * sizeof *tmp);
    for (int i = 0; i < n; i++) {
        double w = (i == ts->n - 1) ? ts->last_w : ts->bin;
        double p = 0;
        for (int c = 0; c < TS_NCAT; c++) p += ts->pkts[c][i];
        rate[i] = p / w;
        tmp[i] = rate[i];
    }
    double med = median_inplace(tmp, (size_t)n);
    for (int i = 0; i < n; i++) tmp[i] = fabs(rate[i] - med);
    double mad = median_inplace(tmp, (size_t)n) * 1.4826;
    /* dolne ograniczenie rozrzutu: szum Poissona liczby pakietów w przedziale,
     * żeby przy rzadkim ruchu (MAD = 0) pojedyncze pakiety nie były "skokami" */
    double cnt = med * ts->bin;
    double pois = sqrt(cnt > 1 ? cnt : 1) / ts->bin;
    if (mad < pois) mad = pois;
    double thr = med + A->cfg->spike_k * mad;
    if (thr < 3 * med) thr = 3 * med;
    double min_excess = 50.0;                           /* pakietów ponad medianę */

    /* przedziały ponad progiem rozdzielone przerwą <= max(2 przedziały, 2 s)
     * łączone są w jedno zdarzenie */
    int gap = (int)ceil(2.0 / ts->bin);
    if (gap < 2) gap = 2;
#define HOT(j) (rate[j] > thr && (rate[j] - med) * ts->bin >= min_excess)
    VEC(spike_t) sp = {0};
    for (int i = 0; i < n;) {
        if (!HOT(i)) { i++; continue; }
        spike_t s;
        memset(&s, 0, sizeof s);
        s.t0 = i * ts->bin;
        int j = i, last = i;
        while (j < n && (HOT(j) || j - last <= gap)) {
            if (HOT(j)) {
                last = j;
                if (rate[j] > s.peak) s.peak = rate[j];
            }
            j++;
        }
        for (int m = i; m <= last; m++)
            for (int c = 0; c < TS_NCAT; c++) {
                s.cat[c] += ts->pkts[c][m];
                s.pkts += ts->pkts[c][m];
            }
        s.t1 = (last + 1) * ts->bin;
        if (s.t1 > A->duration) s.t1 = A->duration;
        VEC_PUSH(sp, s);
        i = last + 1;
    }
#undef HOT
    qsort(sp.v, sp.n, sizeof *sp.v, cmp_spike);
    static const char *const cat_name[TS_NCAT] = {"TCP", "UDP", "inne"};
    for (size_t k = 0; k < sp.n && k < 5; k++) {
        spike_t *s = &sp.v[k];
        int dom = 0;
        for (int c = 1; c < TS_NCAT; c++)
            if (s->cat[c] > s->cat[dom]) dom = c;
        int sev = (med <= 0 || s->peak >= 10 * med) ? SEV_MEDIUM : SEV_LOW;
        anomaly_t *a = add(A, AN_SPIKE, sev, s->t0, s->t1, s->peak,
                           "Skok natężenia ruchu do %s pak./s", fmt_num(s->peak, 0));
        det(a, "W przedziale %s - %s od początku zrzutu natężenie ruchu osiągnęło %s pak./s "
               "przy medianie %s pak./s (próg detekcji %s pak./s). W tym czasie przesłano %s "
               "pakietów; dominujący protokół: %s (%s).",
            fmt_dur(s->t0), fmt_dur(s->t1), fmt_num(s->peak, 0), fmt_num(med, 1),
            fmt_num(thr, 1), fmt_num(s->pkts, 0), cat_name[dom],
            fmt_pct(s->pkts > 0 ? s->cat[dom] / s->pkts : 0, 0));
    }
    VEC_FREE(sp);
    free(rate);
    free(tmp);
}

/* ---- Detektory na poziomie hostów ---- */

static int is_scan_target(const analysis_t *A, const ipaddr_t *ip)
{
    for (size_t i = 0; i < A->an.n; i++) {
        const anomaly_t *a = &A->an.v[i];
        if ((a->type == AN_PORT_SCAN || a->type == AN_SYN_FLOOD || a->type == AN_UDP_SCAN) &&
            ip_eq(&a->dst, ip))
            return 1;
    }
    return 0;
}

static void detect_hosts(analysis_t *A)
{
    const config_t *cfg = A->cfg;
    for (size_t i = 0; i < A->nhosts; i++) {
        host_t *h = &A->hosts[i];

        /* nieprawidłowe kombinacje flag TCP */
        uint32_t bad = 0;
        for (int k = 0; k < BF_COUNT; k++) bad += h->bad_flags[k];
        if (bad >= 5) {
            anomaly_t *a = add(A, AN_BAD_FLAGS, bad >= 100 ? SEV_HIGH : SEV_MEDIUM,
                               h->bad_t0, h->bad_t1, bad,
                               "Nieprawidłowe flagi TCP od %s", ip_str(&h->ip));
            a->src = h->ip;
            det(a, "Host %s wysłał %u segmentów TCP z kombinacją flag niewystępującą w poprawnej "
                   "komunikacji (NULL: %u, FIN bez ACK: %u, XMAS: %u, SYN+FIN: %u, SYN+RST: %u). "
                   "Takie pakiety są typowe dla skanowania typu stealth (np. nmap -sN/-sF/-sX) "
                   "i prób omijania zapór.",
                ip_str(&h->ip), bad, h->bad_flags[BF_NULL], h->bad_flags[BF_FIN],
                h->bad_flags[BF_XMAS], h->bad_flags[BF_SYNFIN], h->bad_flags[BF_SYNRST]);
        }

        /* nadmiar RST (z pominięciem celów skanowania - tam RST jest naturalny) */
        if (h->rst_sent >= (uint32_t)cfg->rst_min && h->tcp_tx > 0 &&
            (double)h->rst_sent / h->tcp_tx >= 0.2 && !is_scan_target(A, &h->ip)) {
            anomaly_t *a = add(A, AN_RST, SEV_LOW, -1, -1, h->rst_sent,
                               "Nadmiar segmentów RST od %s", ip_str(&h->ip));
            a->src = h->ip;
            det(a, "Host %s wysłał %u segmentów RST, co stanowi %s wysłanych przez niego "
                   "segmentów TCP. Może to oznaczać odrzucanie połączeń do zamkniętych portów, "
                   "awarie aplikacji lub aktywne zrywanie połączeń.",
                ip_str(&h->ip), h->rst_sent, fmt_pct((double)h->rst_sent / h->tcp_tx, 1));
        }

        /* tunelowanie DNS */
        if (h->dns_susp >= (uint32_t)cfg->dns_tunnel_min) {
            anomaly_t *a = add(A, AN_DNS_TUNNEL,
                               h->dns_susp >= 10u * (uint32_t)cfg->dns_tunnel_min ? SEV_HIGH : SEV_MEDIUM,
                               h->dns_t0, h->dns_t1, h->dns_susp,
                               "Podejrzane zapytania DNS od %s", ip_str(&h->ip));
            a->src = h->ip;
            det(a, "Klient %s wysłał %u zapytań DNS (z %u) o nazwach z długimi etykietami o "
                   "wysokiej entropii, charakterystycznych dla tunelowania danych przez DNS lub "
                   "komunikacji złośliwego oprogramowania. Przykład: %s",
                ip_str(&h->ip), h->dns_susp, h->dns_q, h->dns_example);
        }

        /* NXDOMAIN - możliwe domeny generowane algorytmicznie */
        if (h->dns_nx_rx >= (uint32_t)cfg->nxdomain_min && h->dns_resp_rx > 0 &&
            (double)h->dns_nx_rx / h->dns_resp_rx >= 0.5) {
            anomaly_t *a = add(A, AN_DNS_NXDOMAIN, SEV_MEDIUM, -1, -1, h->dns_nx_rx,
                               "Nadmiar odpowiedzi NXDOMAIN dla %s", ip_str(&h->ip));
            a->dst = h->ip;
            det(a, "Klient %s otrzymał %u odpowiedzi NXDOMAIN (%s wszystkich odpowiedzi DNS). "
                   "Wiele zapytań o nieistniejące domeny jest typowe dla złośliwego "
                   "oprogramowania korzystającego z algorytmów DGA albo dla błędnej konfiguracji.",
                ip_str(&h->ip), h->dns_nx_rx,
                fmt_pct((double)h->dns_nx_rx / h->dns_resp_rx, 0));
        }
    }
}

/* ---- Jakość połączeń TCP ---- */

static int g_cmp_mode;
static const flowtable_t *g_ft;
static int cmp_flow_metric(const void *x, const void *y)
{
    const flow_t *a = &g_ft->v[*(const int32_t *)x], *b = &g_ft->v[*(const int32_t *)y];
    uint32_t ma = g_cmp_mode ? a->d[0].zerowin + a->d[1].zerowin : a->d[0].retrans + a->d[1].retrans;
    uint32_t mb = g_cmp_mode ? b->d[0].zerowin + b->d[1].zerowin : b->d[0].retrans + b->d[1].retrans;
    return (ma < mb) - (ma > mb);
}

static const char *flow_label(const flow_t *f)
{
    static char buf[4][160];
    static int k;
    k = (k + 1) & 3;
    const char *fmt = f->cli.v == 6 ? "[%s]:%u -> [%s]:%u" : "%s:%u -> %s:%u";
    snprintf(buf[k], sizeof buf[k], fmt, ip_str(&f->cli), f->cport, ip_str(&f->srv), f->sport);
    return buf[k];
}

static void detect_tcp_quality(analysis_t *A)
{
    const config_t *cfg = A->cfg;
    global_t *g = &A->g;
    const timeseries_t *ts = &A->ts;

    if (g->data_segs >= 100 && g->retrans >= 20) {
        double rate = (double)g->retrans / g->data_segs;
        if (rate >= cfg->retrans_warn) {
            double t0 = -1, t1 = -1;
            for (int i = 0; i < ts->n; i++)
                if (ts->retrans[i] > 0) {
                    if (t0 < 0) t0 = i * ts->bin;
                    t1 = (i + 1) * ts->bin;
                }
            if (t1 > A->duration) t1 = A->duration;
            anomaly_t *a = add(A, AN_RETRANS, rate >= 5 * cfg->retrans_warn ? SEV_HIGH : SEV_MEDIUM,
                               t0, t1, rate, "Wysoki odsetek retransmisji TCP (%s)", fmt_pct(rate, 1));
            det(a, "Retransmitowano %s z %s segmentów TCP z danymi (%s; próg %s). Dodatkowo: "
                   "segmenty poza kolejnością %s, luki w numeracji %s, zduplikowane ACK %s. "
                   "Wskazuje to na utratę pakietów, przeciążenie łącza lub problemy z MTU.",
                fmt_int(g->retrans), fmt_int(g->data_segs), fmt_pct(rate, 2),
                fmt_pct(cfg->retrans_warn, 1), fmt_int(g->ooo), fmt_int(g->lost), fmt_int(g->dupack));
        }
    }

    /* pojedyncze połączenia z dużą liczbą retransmisji oraz zerowym oknem */
    const flowtable_t *ft = &A->ft;
    int32_t *idx = xmalloc((ft->n ? ft->n : 1) * sizeof *idx);
    size_t n = 0;
    double flow_thr = cfg->retrans_warn * 2.5 > 0.05 ? cfg->retrans_warn * 2.5 : 0.05;
    for (size_t i = 0; i < ft->n; i++) {
        const flow_t *f = &ft->v[i];
        if (f->proto != IPP_TCP) continue;
        uint32_t rt = f->d[0].retrans + f->d[1].retrans;
        uint32_t ds = f->d[0].data_segs + f->d[1].data_segs;
        if (rt >= 10 && ds > 0 && (double)rt / ds >= flow_thr) idx[n++] = (int32_t)i;
    }
    g_ft = ft;
    g_cmp_mode = 0;
    qsort(idx, n, sizeof *idx, cmp_flow_metric);
    for (size_t k = 0; k < n && k < 5; k++) {
        const flow_t *f = &ft->v[idx[k]];
        uint32_t rt = f->d[0].retrans + f->d[1].retrans;
        uint32_t ds = f->d[0].data_segs + f->d[1].data_segs;
        anomaly_t *a = add(A, AN_RETRANS_FLOW, SEV_LOW, f->first, f->last, rt,
                           "Retransmisje w połączeniu %s", flow_label(f));
        a->src = f->cli;
        a->dst = f->srv;
        det(a, "Połączenie %s: %u retransmisji na %u segmentów z danymi (%s), czas trwania %s",
            flow_label(f), rt, ds, fmt_pct((double)rt / ds, 1), fmt_dur(f->last - f->first));
        if (f->rtt > 0) det(a, ", RTT uzgadniania %s", fmt_dur(f->rtt));
        det(a, ". Retransmisje: klient -> serwer %u, serwer -> klient %u.", f->d[0].retrans, f->d[1].retrans);
    }

    n = 0;
    uint64_t zw_events = 0;
    for (size_t i = 0; i < ft->n; i++) {
        const flow_t *f = &ft->v[i];
        if (f->proto == IPP_TCP && f->d[0].zerowin + f->d[1].zerowin > 0) {
            idx[n++] = (int32_t)i;
            zw_events += f->d[0].zerowin + f->d[1].zerowin;
        }
    }
    if (n > 0) {
        g_cmp_mode = 1;
        qsort(idx, n, sizeof *idx, cmp_flow_metric);
        const flow_t *f0 = &ft->v[idx[0]];
        anomaly_t *a = add(A, AN_ZERO_WINDOW, n >= 10 ? SEV_MEDIUM : SEV_LOW, f0->first, f0->last,
                           (double)zw_events, "Zerowe okno TCP w %zu połączeni%s", n, n == 1 ? "u" : "ach");
        det(a, "W %zu połączeniach odbiorca ogłosił zerowe okno (%s segmentów), czyli wstrzymał "
               "przyjmowanie danych z powodu zapełnionego bufora - zwykle oznacza to przeciążoną "
               "lub zbyt wolną aplikację odbiorczą. Najwięcej zdarzeń: ",
            n, fmt_int(zw_events));
        for (size_t k = 0; k < n && k < 3; k++) {
            const flow_t *f = &ft->v[idx[k]];
            det(a, "%s%s (%u; zerowe okno ogłaszał %s)", k ? "; " : "", flow_label(f),
                f->d[0].zerowin + f->d[1].zerowin,
                f->d[1].zerowin >= f->d[0].zerowin ? "serwer" : "klient");
        }
        det(a, ".");
    }
    free(idx);
}

/* ---- Pozostałe detektory globalne ---- */

static void detect_misc(analysis_t *A)
{
    global_t *g = &A->g;

    if (g->land > 0) {
        anomaly_t *a = add(A, AN_LAND, SEV_HIGH, -1, -1, (double)g->land,
                           "Pakiety typu LAND (%s)", fmt_int(g->land));
        det(a, "Wykryto %s segmentów SYN, w których adres i port źródłowy są równe docelowym. "
               "Jest to znany atak odmowy usługi (LAND) na podatne stosy TCP/IP.", fmt_int(g->land));
    }

    if (g->icmp_unreach >= 50) {
        const host_t *top = NULL;
        for (size_t i = 0; i < A->nhosts; i++)
            if (!top || A->hosts[i].icmp_unreach_sent > top->icmp_unreach_sent) top = &A->hosts[i];
        anomaly_t *a = add(A, AN_ICMP_UNREACH, SEV_LOW, -1, -1, (double)g->icmp_unreach,
                           "%s komunikatów ICMP \"cel nieosiągalny\"", fmt_int(g->icmp_unreach));
        det(a, "Zaobserwowano %s komunikatów ICMP/ICMPv6 \"cel nieosiągalny\" (w tym \"port "
               "nieosiągalny\": %s). Najwięcej wysłał host %s (%u). Duża liczba takich komunikatów "
               "towarzyszy skanowaniu UDP, błędom routingu lub próbom połączeń z wyłączonymi usługami.",
            fmt_int(g->icmp_unreach), fmt_int(g->icmp_port_unreach),
            top ? ip_str(&top->ip) : "?", top ? top->icmp_unreach_sent : 0);
        if (top) a->src = top->ip;
    }

    uint64_t bad = g->malformed + g->l4_bad;
    if (bad > 0) {
        int sev = (double)bad / (g->pkts ? g->pkts : 1) > 0.01 ? SEV_MEDIUM : SEV_LOW;
        anomaly_t *a = add(A, AN_MALFORMED, sev, -1, -1, (double)bad,
                           "Pakiety z uszkodzonymi nagłówkami (%s)", fmt_int(bad));
        det(a, "%s pakietów ma niespójne nagłówki (warstwa IP: %s, warstwa TCP/UDP: %s). "
               "Przyczyną może być uszkodzenie danych, błędne oprogramowanie lub celowo "
               "spreparowane pakiety (fuzzing, omijanie systemów IDS).",
            fmt_int(bad), fmt_int(g->malformed), fmt_int(g->l4_bad));
        if (g->trunc)
            det(a, " Dodatkowo %s ramek było zbyt krótkich, by odczytać nagłówki.", fmt_int(g->trunc));
    }

    /* protokoły przesyłające dane uwierzytelniające otwartym tekstem */
    static const struct { uint8_t proto; uint16_t port; } clear[] = {
        {IPP_TCP, 21}, {IPP_TCP, 23}, {IPP_TCP, 110}, {IPP_TCP, 143}, {IPP_TCP, 512},
        {IPP_TCP, 513}, {IPP_TCP, 514}, {IPP_UDP, 69}, {IPP_UDP, 161},
    };
    uint32_t cnt[ARRAY_LEN(clear)] = {0};
    double t0 = -1, t1 = -1;
    uint32_t total = 0;
    const flow_t *example = NULL;
    for (size_t i = 0; i < A->ft.n; i++) {
        const flow_t *f = &A->ft.v[i];
        int used = f->proto == IPP_TCP
                       ? (f->established || f->outcome == TO_MIDSTREAM) && f->d[0].payload + f->d[1].payload > 0
                       : f->d[1].pkts > 0;
        if (!used) continue;
        for (size_t k = 0; k < ARRAY_LEN(clear); k++)
            if (f->proto == clear[k].proto && f->sport == clear[k].port) {
                cnt[k]++;
                total++;
                if (!example) example = f;
                if (t0 < 0 || f->first < t0) t0 = f->first;
                if (f->last > t1) t1 = f->last;
            }
    }
    if (total > 0) {
        anomaly_t *a = add(A, AN_CLEARTEXT, SEV_LOW, t0, t1, total,
                           "Protokoły nieszyfrowane (%u połącz%s)", total, total == 1 ? "enie" : "eń");
        det(a, "Wykryto użycie protokołów przesyłających dane, w tym dane logowania, bez "
               "szyfrowania: ");
        int first = 1;
        for (size_t k = 0; k < ARRAY_LEN(clear); k++)
            if (cnt[k]) {
                det(a, "%s%s/%s: %u", first ? "" : ", ", fmt_port(clear[k].proto, clear[k].port),
                    clear[k].proto == IPP_TCP ? "TCP" : "UDP", cnt[k]);
                first = 0;
            }
        det(a, ". Przykład: %s. Zalecane jest zastąpienie ich wersjami szyfrowanymi "
               "(SSH, SFTP, IMAPS, SNMPv3).", flow_label(example));
        a->src = example->cli;
        a->dst = example->srv;
    }
}

/* ------------------------------------------------------------------ */

static int cmp_anomaly(const void *x, const void *y)
{
    const anomaly_t *a = x, *b = y;
    if (a->sev != b->sev) return b->sev - a->sev;
    if (a->type != b->type) return a->type - b->type;
    return (a->score < b->score) - (a->score > b->score);
}

void anomaly_detect(analysis_t *A)
{
    const flowtable_t *ft = &A->ft;
    rec_t *tcp = xmalloc((ft->n ? ft->n : 1) * sizeof *tcp);
    rec_t *udp = xmalloc((ft->n ? ft->n : 1) * sizeof *udp);
    size_t nt = 0, nu = 0;
    for (size_t i = 0; i < ft->n; i++) {
        const flow_t *f = &ft->v[i];
        rec_t r;
        memset(&r, 0, sizeof r);
        r.a = f->cli;
        r.b = f->srv;
        r.port = f->sport;
        r.t0 = f->first;
        r.t1 = f->last;
        r.outcome = f->outcome;
        if (f->proto == IPP_TCP) {
            if (!f->syn_seen) continue;           /* tylko połączenia inicjowane SYN */
            r.answered = f->synack_seen;
            r.rejected = f->rejected;
            tcp[nt++] = r;
        } else {
            /* sondy traceroute (UDP 33434-33534) nie są skanowaniem */
            if (f->sport >= 33434 && f->sport <= 33534) continue;
            r.answered = f->d[1].pkts > 0;
            r.rejected = f->icmp_unreach > 0;
            udp[nu++] = r;
        }
    }

    detect_vertical(A, tcp, nt, IPP_TCP);
    detect_vertical(A, udp, nu, IPP_UDP);
    detect_sweep(A, tcp, nt);
    detect_synflood(A, tcp, nt);
    free(tcp);
    free(udp);

    detect_udp_flood(A);
    detect_spikes(A);
    detect_hosts(A);
    detect_tcp_quality(A);
    detect_misc(A);

    qsort(A->an.v, A->an.n, sizeof *A->an.v, cmp_anomaly);
    memset(A->sev_count, 0, sizeof A->sev_count);
    for (size_t i = 0; i < A->an.n; i++) A->sev_count[A->an.v[i].sev]++;
}

const char *anomaly_type_name(int t)
{
    static const char *const n[AN_COUNT] = {
        "Skanowanie portów TCP", "Przeszukiwanie hostów", "Skanowanie portów UDP", "SYN flood",
        "Zalew UDP", "Skok natężenia ruchu", "Nieprawidłowe flagi TCP", "Atak LAND",
        "Wysoki odsetek retransmisji", "Retransmisje w połączeniu", "Nadmiar segmentów RST",
        "Zerowe okno TCP", "Nieudane połączenia", "Podejrzane zapytania DNS", "Nadmiar NXDOMAIN",
        "ICMP: cel nieosiągalny", "Uszkodzone pakiety", "Protokoły nieszyfrowane",
    };
    return (t >= 0 && t < AN_COUNT) ? n[t] : "?";
}

const char *anomaly_type_code(int t)
{
    static const char *const n[AN_COUNT] = {
        "PORT_SCAN", "HOST_SWEEP", "UDP_SCAN", "SYN_FLOOD", "UDP_FLOOD", "TRAFFIC_SPIKE",
        "BAD_TCP_FLAGS", "LAND", "TCP_RETRANS", "TCP_RETRANS_FLOW", "RST_EXCESS",
        "ZERO_WINDOW", "FAILED_CONN", "DNS_TUNNEL", "DNS_NXDOMAIN", "ICMP_UNREACH",
        "MALFORMED", "CLEARTEXT",
    };
    return (t >= 0 && t < AN_COUNT) ? n[t] : "?";
}

const char *sev_name(int s)
{
    static const char *const n[SEV_COUNT] = {"niski", "średni", "wysoki"};
    return (s >= 0 && s < SEV_COUNT) ? n[s] : "?";
}
