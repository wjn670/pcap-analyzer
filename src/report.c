#include "report.h"
#include "figures.h"
#include "pdfdoc.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

long long report_timestamp(void)
{
    const char *e = getenv("SOURCE_DATE_EPOCH");
    if (e && *e) {
        char *end;
        long long v = strtoll(e, &end, 10);
        if (*end == '\0' && v > 0) return v;
    }
    return (long long)time(NULL);
}

static const char *basename_of(const char *p)
{
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

static const char *endpoint(const ipaddr_t *ip, uint16_t port)
{
    static char buf[16][80];
    static int k;
    k = (k + 1) & 15;
    snprintf(buf[k], sizeof buf[k], ip->v == 6 ? "[%s]:%u" : "%s:%u", ip_str(ip), port);
    return buf[k];
}

static const char *host_kind(const ipaddr_t *ip)
{
    if (ip_is_multicast(ip)) return "multi/broadcast";
    if (ip_is_private(ip)) return "prywatny";
    return "publiczny";
}

static double safe_div(double a, double b) { return b > 0 ? a / b : 0; }

/* ---- Strona tytułowa ---- */

static void tile(doc_t *d, double x, double y, double w, double h, const char *label,
                 const char *value, const char *sub)
{
    cairo_t *cr = d->cr;
    set_rgb(cr, (rgb_t){0.957, 0.957, 0.945});
    round_rect(cr, x, y, w, h, 6);
    cairo_fill(cr);
    txt_draw(cr, x + 10, y + 17, label, 8.5, 0, C_INK2, AL_LEFT);
    char buf[128];
    txt_fit(cr, value, 16, 1, w - 20, buf, sizeof buf);
    txt_draw(cr, x + 10, y + 39, buf, 16, 1, C_INK, AL_LEFT);
    if (sub && *sub) txt_draw(cr, x + 10, y + 53, sub, 7.5, 0, C_MUTED, AL_LEFT);
}

static void findings(doc_t *d, const analysis_t *A)
{
    const global_t *g = &A->g;
    char b[768];

    double tcp_b = safe_div((double)g->ip_bytes[PR_TCP], (double)g->bytes);
    double udp_b = safe_div((double)g->ip_bytes[PR_UDP], (double)g->bytes);
    snprintf(b, sizeof b, "Ruch TCP stanowi %s przesłanych bajtów (%s pakietów), UDP - %s bajtów "
                          "(%s pakietów).",
             fmt_pct(tcp_b, 1), fmt_pct(safe_div((double)g->ip_pkts[PR_TCP], (double)g->pkts), 1),
             fmt_pct(udp_b, 1), fmt_pct(safe_div((double)g->ip_pkts[PR_UDP], (double)g->pkts), 1));
    doc_bullet(d, b);

    if (A->nhost_rank > 0) {
        const host_t *h = &A->hosts[A->host_rank[0]];
        double hb = (double)(h->tx_bytes + h->rx_bytes);
        snprintf(b, sizeof b, "Najaktywniejszy host: %s (%s, %s, udział w %s całego ruchu).",
                 ip_str(&h->ip), host_kind(&h->ip), fmt_bytes(hb), fmt_pct(safe_div(hb, (double)g->bytes), 1));
        doc_bullet(d, b);
    }
    if (A->ntcp_port_rank > 0) {
        const port_stat_t *p = &A->tcp_ports[A->tcp_port_rank[0]];
        uint64_t tot = 0;
        for (size_t i = 0; i < A->ntcp_port_rank; i++) tot += A->tcp_ports[A->tcp_port_rank[i]].bytes;
        snprintf(b, sizeof b, "Dominująca usługa TCP: port %s - %s w %s połączeniach (%s bajtów TCP).",
                 fmt_port(IPP_TCP, A->tcp_port_rank[0]), fmt_bytes((double)p->bytes), fmt_int(p->flows),
                 fmt_pct(safe_div((double)p->bytes, (double)tot), 1));
        doc_bullet(d, b);
    }
    if (A->nudp_port_rank > 0) {
        const port_stat_t *p = &A->udp_ports[A->udp_port_rank[0]];
        snprintf(b, sizeof b, "Dominująca usługa UDP: port %s - %s w %s przepływach.",
                 fmt_port(IPP_UDP, A->udp_port_rank[0]), fmt_bytes((double)p->bytes), fmt_int(p->flows));
        doc_bullet(d, b);
    }
    uint64_t attempts = A->tcp_flows - A->outcome[TO_MIDSTREAM];
    uint64_t failed = A->outcome[TO_UNANSWERED] + A->outcome[TO_REJECTED] + A->outcome[TO_HALF_OPEN];
    if (attempts > 0) {
        int n = snprintf(b, sizeof b, "Nawiązano %s z %s prób połączeń TCP",
                         fmt_pct(safe_div((double)(attempts - failed), (double)attempts), 1), fmt_int(attempts));
        if (A->nrtt > 0)
            snprintf(b + n, sizeof b - (size_t)n, "; mediana czasu uzgadniania (RTT) wynosi %s.",
                     fmt_dur(quantile_sorted(A->rtt, A->nrtt, 0.5)));
        else
            snprintf(b + n, sizeof b - (size_t)n, ".");
        doc_bullet(d, b);
    }
    if (g->data_segs > 0) {
        double r = safe_div((double)g->retrans, (double)g->data_segs);
        snprintf(b, sizeof b, "Odsetek retransmisji TCP: %s (%s z %s segmentów z danymi) - %s.",
                 fmt_pct(r, 2), fmt_int(g->retrans), fmt_int(g->data_segs),
                 r >= A->cfg->retrans_warn ? "powyżej progu ostrzeżenia, możliwe straty pakietów"
                                           : "w normie");
        doc_bullet(d, b);
    }
    if (A->an.n == 0) {
        doc_bullet(d, "Przy zastosowanych progach nie wykryto nieprawidłowości.");
    } else {
        snprintf(b, sizeof b, "Wykryto %zu nieprawidłowości: wysokie %d, średnie %d, niskie %d "
                              "(szczegóły w sekcji 8).",
                 A->an.n, A->sev_count[SEV_HIGH], A->sev_count[SEV_MEDIUM], A->sev_count[SEV_LOW]);
        doc_bullet(d, b);
        for (size_t i = 0; i < A->an.n && i < 4; i++) {
            const anomaly_t *a = &A->an.v[i];
            if (a->sev == SEV_LOW) break;
            snprintf(b, sizeof b, "[%s] %s", sev_name(a->sev), a->title);
            doc_bullet(d, b);
        }
    }
}

static void cover(doc_t *d, const analysis_t *A, const char *files, const char *gen)
{
    const global_t *g = &A->g;
    doc_new_page(d, 0);
    cairo_t *cr = d->cr;
    double w = doc_width(d);
    double y = 96;

    txt_draw(cr, d->ml, y, "RAPORT Z ANALIZY RUCHU SIECIOWEGO", 8.5, 1, C_SERIES[0], AL_LEFT);
    y += 14;
    y += doc_wrap(d, d->ml, y, w, A->cfg->title, 24, 1, C_INK, 30, 1);
    y += 4;
    txt_draw(cr, d->ml, y + 12, "Komunikacja TCP i UDP na podstawie plików przechwytywania pakietów", 11.5, 0,
             C_INK2, AL_LEFT);
    y += 28;
    set_rgb(cr, C_AXIS);
    cairo_set_line_width(cr, 0.8);
    cairo_move_to(cr, d->ml, y);
    cairo_line_to(cr, d->ml + w, y);
    cairo_stroke(cr);
    y += 10;

    const char *keys[4] = {"Pliki wejściowe", "Okres przechwytywania", "Czas trwania", "Wygenerowano"};
    char period[160];
    snprintf(period, sizeof period, "%s - %s", fmt_utc(A->t0_ns), fmt_utc(A->t1_ns));
    const char *vals[4] = {files, period, fmt_dur(A->duration), gen};
    for (int i = 0; i < 4; i++) {
        txt_draw(cr, d->ml, y + 11, keys[i], 8.5, 0, C_INK2, AL_LEFT);
        double h = doc_wrap(d, d->ml + 130, y, w - 130, vals[i], 8.5, 0, C_INK, 12, 1);
        y += (h > 13 ? h : 13) + 2;
    }
    y += 14;

    /* kafelki z kluczowymi liczbami */
    double gap = 8, tw = (w - 3 * gap) / 4, th = 62;
    char an_sub[64];
    snprintf(an_sub, sizeof an_sub, "wysokie %d · średnie %d · niskie %d", A->sev_count[SEV_HIGH],
             A->sev_count[SEV_MEDIUM], A->sev_count[SEV_LOW]);
    char an_val[32];
    snprintf(an_val, sizeof an_val, "%zu", A->an.n);
    uint64_t attempts = A->tcp_flows - A->outcome[TO_MIDSTREAM];
    uint64_t failed = A->outcome[TO_UNANSWERED] + A->outcome[TO_REJECTED] + A->outcome[TO_HALF_OPEN];
    char tcp_sub[64];
    snprintf(tcp_sub, sizeof tcp_sub, "nieudane: %s", fmt_pct(safe_div((double)failed, (double)attempts), 1));
    char udp_sub[64];
    snprintf(udp_sub, sizeof udp_sub, "bez odpowiedzi: %s",
             fmt_pct(safe_div((double)A->udp_oneway, (double)A->udp_flows), 1));
    char pk_sub[64];
    snprintf(pk_sub, sizeof pk_sub, "średnio %s pak./s", fmt_num(safe_div((double)g->pkts, A->duration), 1));
    char ip_sub[64];
    snprintf(ip_sub, sizeof ip_sub, "IPv4 %s · IPv6 %s", fmt_pct(safe_div((double)g->ipv4, (double)g->pkts), 0),
             fmt_pct(safe_div((double)g->ipv6, (double)g->pkts), 0));
    char by_sub[64];
    snprintf(by_sub, sizeof by_sub, "śr. ramka %s", fmt_bytes(safe_div((double)g->bytes, (double)g->pkts)));

    tile(d, d->ml, y, tw, th, "Pakiety", fmt_int(g->pkts), pk_sub);
    tile(d, d->ml + (tw + gap), y, tw, th, "Przesłane dane", fmt_bytes((double)g->bytes), by_sub);
    tile(d, d->ml + 2 * (tw + gap), y, tw, th, "Średnia przepływność",
         fmt_bitrate(safe_div(g->bytes * 8.0, A->duration)), fmt_dur(A->duration));
    tile(d, d->ml + 3 * (tw + gap), y, tw, th, "Adresy IP", fmt_int(A->nhosts), ip_sub);
    y += th + gap;
    tile(d, d->ml, y, tw, th, "Połączenia TCP", fmt_int(A->tcp_flows), tcp_sub);
    tile(d, d->ml + (tw + gap), y, tw, th, "Przepływy UDP", fmt_int(A->udp_flows), udp_sub);
    tile(d, d->ml + 2 * (tw + gap), y, tw, th, "Zapytania DNS", fmt_int(A->dns.queries),
         A->dns.queries ? fmt_pct(safe_div((double)A->dns.rcode[3], (double)A->dns.responses), 1) : "");
    if (A->dns.queries) {
        /* dopisek do kafelka DNS */
        set_rgb(cr, (rgb_t){0.957, 0.957, 0.945});
        cairo_rectangle(cr, d->ml + 2 * (tw + gap) + 8, y + 45, tw - 16, 12);
        cairo_fill(cr);
        char s[64];
        snprintf(s, sizeof s, "NXDOMAIN: %s odpowiedzi",
                 fmt_pct(safe_div((double)A->dns.rcode[3], (double)A->dns.responses), 1));
        txt_draw(cr, d->ml + 2 * (tw + gap) + 10, y + 53, s, 7.5, 0, C_MUTED, AL_LEFT);
    }
    tile(d, d->ml + 3 * (tw + gap), y, tw, th, "Nieprawidłowości", an_val, an_sub);
    y += th + 26;

    txt_draw(cr, d->ml, y, "Najważniejsze wnioski", 12.5, 1, C_INK, AL_LEFT);
    d->y = y + 10;
    findings(d, A);
}

/* ---- Sekcje ---- */

static void sec_input(doc_t *d, const analysis_t *A)
{
    const global_t *g = &A->g;
    doc_h1(d, "1. Dane wejściowe");
    char b[1024];
    snprintf(b, sizeof b, "Analizie poddano %d plik%s przechwytywania. Pakiety ze wszystkich plików "
                          "zostały scalone w kolejności znaczników czasu i przeanalizowane jako jeden "
                          "strumień, dzięki czemu zrzuty z kilku interfejsów lub podzielone na części "
                          "tworzą spójną całość. Znaczniki czasu podano w UTC.",
             A->nfiles, A->nfiles == 1 ? "" : (A->nfiles < 5 ? "i" : "ów"));
    doc_text(d, b);

    table_t t;
    table_init(&t, 7);
    table_col(&t, 0, "Plik", 2.2, AL_LEFT);
    table_col(&t, 1, "Typ łącza", 1.3, AL_LEFT);
    table_col(&t, 2, "Pakiety", 0.9, AL_RIGHT);
    table_col(&t, 3, "Bajty", 0.9, AL_RIGHT);
    table_col(&t, 4, "Początek", 1.7, AL_LEFT);
    table_col(&t, 5, "Koniec", 1.7, AL_LEFT);
    table_col(&t, 6, "Snaplen", 0.7, AL_RIGHT);
    for (int i = 0; i < A->nfiles; i++) {
        const input_file_t *f = &A->files[i];
        if (!f->ok) {
            table_add(&t, basename_of(f->path), "błąd odczytu", "-", "-", "-", "-", "-");
            continue;
        }
        char snap[16];
        snprintf(snap, sizeof snap, "%u", f->snaplen);
        table_add(&t, basename_of(f->path), f->dlt_name, fmt_int(f->packets), fmt_bytes((double)f->bytes),
                  f->packets ? fmt_utc(f->first_ns) : "-", f->packets ? fmt_utc(f->last_ns) : "-", snap);
    }
    doc_table(d, &t, "Pliki wejściowe");
    table_free(&t);

    for (int i = 0; i < A->nfiles; i++) {
        const input_file_t *f = &A->files[i];
        if (!f->ok) {
            snprintf(b, sizeof b, "Plik %s nie został przeanalizowany: %s", basename_of(f->path), f->err);
            doc_note(d, b);
        } else if (f->read_error) {
            snprintf(b, sizeof b, "Plik %s jest uszkodzony lub ucięty (%s); przeanalizowano pakiety "
                                  "odczytane przed miejscem błędu.", basename_of(f->path), f->err);
            doc_note(d, b);
        }
        if (f->ok && f->unordered) {
            snprintf(b, sizeof b, "Znaczniki czasu w pliku %s nie są monotoniczne; statystyki czasowe "
                                  "mogą być przybliżone.", basename_of(f->path));
            doc_note(d, b);
        }
    }

    doc_h2(d, "Dekodowanie pakietów");
    const char *k[] = {"Ramki ogółem", "Pakiety IPv4", "Pakiety IPv6", "Ramki nie-IP (w tym ARP)",
                       "Ramki ze znacznikiem VLAN", "Fragmenty IP", "Nagłówki TCP/UDP obcięte (snaplen)",
                       "Ramki zbyt krótkie do zdekodowania", "Pakiety z uszkodzonymi nagłówkami",
                       "Nieobsługiwany typ łącza"};
    char nonip[64], bad[64];
    snprintf(nonip, sizeof nonip, "%s (ARP: %s)", fmt_int(g->nonip), fmt_int(g->arp));
    snprintf(bad, sizeof bad, "%s (IP: %s, TCP/UDP: %s)", fmt_int(g->malformed + g->l4_bad),
             fmt_int(g->malformed), fmt_int(g->l4_bad));
    const char *v[] = {fmt_int(g->pkts), fmt_int(g->ipv4), fmt_int(g->ipv6), nonip, fmt_int(g->vlan),
                       fmt_int(g->fragments), fmt_int(g->l4_trunc), fmt_int(g->trunc), bad,
                       fmt_int(g->unsupported)};
    doc_kv(d, k, v, 10);
}

static void sec_general(doc_t *d, const analysis_t *A)
{
    const global_t *g = &A->g;
    const timeseries_t *ts = &A->ts;
    doc_h1(d, "2. Statystyki ogólne");

    double peak_bps = 0, peak_pps = 0, peak_t = 0, peak_tp = 0;
    for (int i = 0; i < ts->n; i++) {
        double w = (i == ts->n - 1) ? ts->last_w : ts->bin;
        double by = 0, pk = 0;
        for (int c = 0; c < TS_NCAT; c++) { by += ts->bytes[c][i]; pk += ts->pkts[c][i]; }
        if (by * 8 / w > peak_bps) { peak_bps = by * 8 / w; peak_t = i * ts->bin; }
        if (pk / w > peak_pps) { peak_pps = pk / w; peak_tp = i * ts->bin; }
    }
    size_t priv = 0, pub = 0, mc = 0;
    for (size_t i = 0; i < A->nhosts; i++) {
        if (ip_is_multicast(&A->hosts[i].ip)) mc++;
        else if (ip_is_private(&A->hosts[i].ip)) priv++;
        else pub++;
    }
    char pk[96], pp[96], hosts[96];
    snprintf(pk, sizeof pk, "%s (w przedziale od %s)", fmt_bitrate(peak_bps), fmt_dur(peak_t));
    snprintf(pp, sizeof pp, "%s pak./s (w przedziale od %s)", fmt_num(peak_pps, 0), fmt_dur(peak_tp));
    snprintf(hosts, sizeof hosts, "%s (prywatne %zu, publiczne %zu, multi/broadcast %zu)",
             fmt_int(A->nhosts), priv, pub, mc);
    const char *k[] = {"Liczba pakietów", "Liczba bajtów", "Czas trwania zrzutu",
                       "Średnie natężenie", "Średnia przepływność", "Średni rozmiar ramki",
                       "Szczytowa przepływność", "Szczytowe natężenie", "Unikalne adresy IP",
                       "Połączenia TCP / przepływy UDP"};
    char avgp[64], fl[96];
    snprintf(avgp, sizeof avgp, "%s pak./s", fmt_num(safe_div((double)g->pkts, A->duration), 1));
    snprintf(fl, sizeof fl, "%s / %s", fmt_int(A->tcp_flows), fmt_int(A->udp_flows));
    const char *v[] = {fmt_int(g->pkts), fmt_bytes((double)g->bytes), fmt_dur(A->duration), avgp,
                       fmt_bitrate(safe_div(g->bytes * 8.0, A->duration)),
                       fmt_bytes(safe_div((double)g->bytes, (double)g->pkts)), pk, pp, hosts, fl};
    doc_kv(d, k, v, 10);

    doc_h2(d, "Protokoły");
    doc_figure(d, A, FIG_PROTOCOLS);
    table_t t;
    table_init(&t, 6);
    table_col(&t, 0, "Protokół", 1.6, AL_LEFT);
    table_col(&t, 1, "Pakiety", 1, AL_RIGHT);
    table_col(&t, 2, "Udział", 0.8, AL_RIGHT);
    table_col(&t, 3, "Bajty", 1, AL_RIGHT);
    table_col(&t, 4, "Udział", 0.8, AL_RIGHT);
    table_col(&t, 5, "Średnia ramka", 1, AL_RIGHT);
    static const char *const pn[PR_COUNT] = {"TCP", "UDP", "ICMP / ICMPv6", "inne protokoły IP"};
    uint64_t ipp = 0, ipb = 0;
    for (int p = 0; p < PR_COUNT; p++) {
        ipp += g->ip_pkts[p];
        ipb += g->ip_bytes[p];
        table_add(&t, pn[p], fmt_int(g->ip_pkts[p]), fmt_pct(safe_div((double)g->ip_pkts[p], (double)g->pkts), 1),
                  fmt_bytes((double)g->ip_bytes[p]), fmt_pct(safe_div((double)g->ip_bytes[p], (double)g->bytes), 1),
                  fmt_bytes(safe_div((double)g->ip_bytes[p], (double)g->ip_pkts[p])));
    }
    table_add(&t, "ramki nie-IP", fmt_int(g->pkts - ipp), fmt_pct(safe_div((double)(g->pkts - ipp), (double)g->pkts), 1),
              fmt_bytes((double)(g->bytes - ipb)), fmt_pct(safe_div((double)(g->bytes - ipb), (double)g->bytes), 1),
              fmt_bytes(safe_div((double)(g->bytes - ipb), (double)(g->pkts - ipp))));
    doc_table(d, &t, "Udział protokołów");
    table_free(&t);

    doc_h2(d, "Rozmiary ramek");
    doc_text(d, "Rozkład rozmiarów ramek pozwala rozpoznać charakter ruchu: krótkie ramki "
                "(do 128 B) to zwykle potwierdzenia TCP, zapytania DNS i ruch sterujący, a ramki "
                "bliskie 1500 B - transfer danych z pełnym rozmiarem segmentu (MSS).");
    doc_figure(d, A, FIG_SIZES);
}

static int cmp_bin_bytes(const void *x, const void *y);
static const timeseries_t *g_ts;

static int cmp_bin_bytes(const void *x, const void *y)
{
    int a = *(const int *)x, b = *(const int *)y;
    double ba = g_ts->bytes[0][a] + g_ts->bytes[1][a] + g_ts->bytes[2][a];
    double bb = g_ts->bytes[0][b] + g_ts->bytes[1][b] + g_ts->bytes[2][b];
    return (ba < bb) - (ba > bb);
}

static void sec_time(doc_t *d, const analysis_t *A)
{
    const timeseries_t *ts = &A->ts;
    doc_h1(d, "3. Ruch w czasie");
    char b[512];
    snprintf(b, sizeof b, "Czas przechwytywania (%s) podzielono na %d przedziałów o szerokości %s. "
                          "Wykresy przedstawiają średnią przepływność i natężenie ruchu w każdym "
                          "przedziale z podziałem na TCP, UDP i pozostały ruch. Pasy w tle oznaczają "
                          "wykryte skoki natężenia (sekcja 8).",
             fmt_dur(A->duration), ts->n, fmt_dur(ts->bin));
    doc_text(d, b);
    doc_figure(d, A, FIG_THROUGHPUT);
    doc_figure(d, A, FIG_PACKET_RATE);

    int *idx = xmalloc((size_t)ts->n * sizeof *idx);
    for (int i = 0; i < ts->n; i++) idx[i] = i;
    g_ts = ts;
    qsort(idx, (size_t)ts->n, sizeof *idx, cmp_bin_bytes);
    table_t t;
    table_init(&t, 6);
    table_col(&t, 0, "Przedział (od początku)", 1.8, AL_LEFT);
    table_col(&t, 1, "Pakiety", 1, AL_RIGHT);
    table_col(&t, 2, "Bajty", 1, AL_RIGHT);
    table_col(&t, 3, "Przepływność", 1.1, AL_RIGHT);
    table_col(&t, 4, "TCP", 0.7, AL_RIGHT);
    table_col(&t, 5, "UDP", 0.7, AL_RIGHT);
    int top = ts->n < 8 ? ts->n : 8;
    for (int k = 0; k < top; k++) {
        int i = idx[k];
        double w = (i == ts->n - 1) ? ts->last_w : ts->bin;
        double by = ts->bytes[0][i] + ts->bytes[1][i] + ts->bytes[2][i];
        double pk = ts->pkts[0][i] + ts->pkts[1][i] + ts->pkts[2][i];
        if (by <= 0) break;
        char range[96];
        snprintf(range, sizeof range, "%s - %s", fmt_dur(i * ts->bin), fmt_dur(i * ts->bin + w));
        table_add(&t, range, fmt_num(pk, 0), fmt_bytes(by), fmt_bitrate(by * 8 / w),
                  fmt_pct(safe_div(ts->bytes[0][i], by), 0), fmt_pct(safe_div(ts->bytes[1][i], by), 0));
    }
    free(idx);
    doc_table(d, &t, "Przedziały czasu o największym wolumenie ruchu");
    table_free(&t);
}

static void sec_hosts(doc_t *d, const analysis_t *A)
{
    const global_t *g = &A->g;
    doc_h1(d, "4. Hosty i usługi");
    doc_text(d, "Ranking hostów uwzględnia wszystkie bajty wysłane i odebrane przez dany adres IP. "
                "Usługi przypisano do portu po stronie serwera, czyli strony odpowiadającej na "
                "inicjację połączenia (ustalanej na podstawie flagi SYN lub, gdy jej brak, portów "
                "dobrze znanych).");
    doc_figure(d, A, FIG_TOP_HOSTS);

    table_t t;
    table_init(&t, 8);
    table_col(&t, 0, "Adres IP", 2.4, AL_LEFT);
    table_col(&t, 1, "Typ", 1.1, AL_LEFT);
    table_col(&t, 2, "Wysłane", 0.9, AL_RIGHT);
    table_col(&t, 3, "Odebrane", 0.9, AL_RIGHT);
    table_col(&t, 4, "Pakiety", 0.9, AL_RIGHT);
    table_col(&t, 5, "Inicjowane", 0.8, AL_RIGHT);
    table_col(&t, 6, "Przyjęte", 0.8, AL_RIGHT);
    table_col(&t, 7, "Udział", 0.7, AL_RIGHT);
    size_t n = A->nhost_rank < (size_t)A->cfg->top_n ? A->nhost_rank : (size_t)A->cfg->top_n;
    for (size_t i = 0; i < n; i++) {
        const host_t *h = &A->hosts[A->host_rank[i]];
        table_add(&t, ip_str(&h->ip), host_kind(&h->ip), fmt_bytes((double)h->tx_bytes),
                  fmt_bytes((double)h->rx_bytes), fmt_int(h->tx_pkts + h->rx_pkts),
                  fmt_int(h->flows_out), fmt_int(h->flows_in),
                  fmt_pct(safe_div((double)(h->tx_bytes + h->rx_bytes), (double)g->bytes), 1));
    }
    doc_table(d, &t, "Najaktywniejsze hosty (przepływy inicjowane i przyjęte)");
    table_free(&t);

    for (int tcp = 1; tcp >= 0; tcp--) {
        size_t nr = tcp ? A->ntcp_port_rank : A->nudp_port_rank;
        const uint16_t *rank = tcp ? A->tcp_port_rank : A->udp_port_rank;
        const port_stat_t *ps = tcp ? A->tcp_ports : A->udp_ports;
        doc_h2(d, tcp ? "Usługi TCP" : "Usługi UDP");
        if (nr == 0) {
            doc_text(d, tcp ? "Brak ruchu TCP." : "Brak ruchu UDP.");
            continue;
        }
        doc_figure(d, A, tcp ? FIG_TCP_PORTS : FIG_UDP_PORTS);
        uint64_t tot = 0;
        for (size_t i = 0; i < nr; i++) tot += ps[rank[i]].bytes;
        table_init(&t, tcp ? 6 : 5);
        table_col(&t, 0, "Port (usługa)", 1.8, AL_LEFT);
        table_col(&t, 1, tcp ? "Połączenia" : "Przepływy", 1, AL_RIGHT);
        if (tcp) table_col(&t, 2, "Nieudane", 1, AL_RIGHT);
        table_col(&t, tcp ? 3 : 2, "Pakiety", 1, AL_RIGHT);
        table_col(&t, tcp ? 4 : 3, "Bajty", 1, AL_RIGHT);
        table_col(&t, tcp ? 5 : 4, "Udział", 0.8, AL_RIGHT);
        size_t m = nr < (size_t)A->cfg->top_n ? nr : (size_t)A->cfg->top_n;
        for (size_t i = 0; i < m; i++) {
            const port_stat_t *p = &ps[rank[i]];
            if (tcp)
                table_add(&t, fmt_port(IPP_TCP, rank[i]), fmt_int(p->flows), fmt_int(p->failed),
                          fmt_int(p->pkts), fmt_bytes((double)p->bytes),
                          fmt_pct(safe_div((double)p->bytes, (double)tot), 1));
            else
                table_add(&t, fmt_port(IPP_UDP, rank[i]), fmt_int(p->flows), fmt_int(p->pkts),
                          fmt_bytes((double)p->bytes), fmt_pct(safe_div((double)p->bytes, (double)tot), 1));
        }
        char cap[96];
        snprintf(cap, sizeof cap, "Usługi %s według wolumenu (%zu różnych portów serwera)", tcp ? "TCP" : "UDP", nr);
        doc_table(d, &t, cap);
        table_free(&t);
    }
}

static void flows_table(doc_t *d, const analysis_t *A, int tcp)
{
    const int32_t *rank = tcp ? A->tcp_flow_rank : A->udp_flow_rank;
    size_t nr = tcp ? A->ntcp_flow_rank : A->nudp_flow_rank;
    size_t n = nr < (size_t)A->cfg->top_n ? nr : (size_t)A->cfg->top_n;
    table_t t;
    if (tcp) {
        table_init(&t, 8);
        table_col(&t, 0, "Klient", 2.0, AL_LEFT);
        table_col(&t, 1, "Serwer", 2.0, AL_LEFT);
        table_col(&t, 2, "Bajty", 0.85, AL_RIGHT);
        table_col(&t, 3, "Pakiety", 0.8, AL_RIGHT);
        table_col(&t, 4, "Czas", 0.85, AL_RIGHT);
        table_col(&t, 5, "Stan", 1.5, AL_LEFT);
        table_col(&t, 6, "RTT", 0.75, AL_RIGHT);
        table_col(&t, 7, "Retr.", 0.55, AL_RIGHT);
    } else {
        table_init(&t, 7);
        table_col(&t, 0, "Klient", 2.0, AL_LEFT);
        table_col(&t, 1, "Serwer", 2.0, AL_LEFT);
        table_col(&t, 2, "Bajty K->S", 0.9, AL_RIGHT);
        table_col(&t, 3, "Bajty S->K", 0.9, AL_RIGHT);
        table_col(&t, 4, "Pakiety", 0.8, AL_RIGHT);
        table_col(&t, 5, "Czas", 0.9, AL_RIGHT);
        table_col(&t, 6, "Usługa", 0.9, AL_LEFT);
    }
    for (size_t i = 0; i < n; i++) {
        const flow_t *f = &A->ft.v[rank[i]];
        const char *svc = port_service(f->proto, f->sport);
        if (tcp) {
            char rt[16];
            snprintf(rt, sizeof rt, "%u", f->d[0].retrans + f->d[1].retrans);
            table_add(&t, endpoint(&f->cli, f->cport), endpoint(&f->srv, f->sport),
                      fmt_bytes((double)flow_bytes(f)), fmt_int(flow_pkts(f)), fmt_dur(f->last - f->first),
                      tcp_outcome_name(f->outcome), f->rtt > 0 ? fmt_dur(f->rtt) : "-", rt);
        } else {
            table_add(&t, endpoint(&f->cli, f->cport), endpoint(&f->srv, f->sport),
                      fmt_bytes((double)f->d[0].bytes), fmt_bytes((double)f->d[1].bytes),
                      fmt_int(flow_pkts(f)), fmt_dur(f->last - f->first), svc ? svc : "-");
        }
    }
    doc_table(d, &t, tcp ? "Największe połączenia TCP" : "Największe przepływy UDP");
    table_free(&t);
}

static void sec_tcp(doc_t *d, const analysis_t *A)
{
    const global_t *g = &A->g;
    doc_h1(d, "5. Analiza TCP");
    if (A->tcp_flows == 0) {
        doc_text(d, "W zrzucie nie wykryto ruchu TCP.");
        return;
    }
    doc_text(d, "Każde połączenie TCP jest śledzone od segmentu SYN do zamknięcia (FIN) lub "
                "przerwania (RST). Na podstawie numerów sekwencyjnych wykrywane są retransmisje, "
                "segmenty poza kolejnością i luki w numeracji, a z potwierdzeń - zduplikowane ACK "
                "i ogłoszenia zerowego okna. Czas uzgadniania (RTT) mierzony jest od segmentu SYN "
                "do potwierdzenia klienta, co odpowiada pełnemu czasowi obiegu niezależnie od "
                "miejsca przechwytywania.");
    uint64_t attempts = A->tcp_flows - A->outcome[TO_MIDSTREAM];
    uint64_t failed = A->outcome[TO_UNANSWERED] + A->outcome[TO_REJECTED] + A->outcome[TO_HALF_OPEN];
    char est[96], fail[160], rtt[160], rtr[96];
    snprintf(est, sizeof est, "%s (%s prób)", fmt_int(attempts - failed),
             fmt_pct(safe_div((double)(attempts - failed), (double)attempts), 1));
    snprintf(fail, sizeof fail, "%s (bez odpowiedzi %s, odrzucone %s, półotwarte %s)", fmt_int(failed),
             fmt_int(A->outcome[TO_UNANSWERED]), fmt_int(A->outcome[TO_REJECTED]),
             fmt_int(A->outcome[TO_HALF_OPEN]));
    if (A->nrtt)
        snprintf(rtt, sizeof rtt, "min %s · mediana %s · 95. percentyl %s · maks. %s",
                 fmt_dur(A->rtt[0]), fmt_dur(quantile_sorted(A->rtt, A->nrtt, 0.5)),
                 fmt_dur(quantile_sorted(A->rtt, A->nrtt, 0.95)), fmt_dur(A->rtt[A->nrtt - 1]));
    else
        snprintf(rtt, sizeof rtt, "brak pełnych uzgodnień w zrzucie");
    snprintf(rtr, sizeof rtr, "%s (%s segmentów z danymi)", fmt_int(g->retrans),
             fmt_pct(safe_div((double)g->retrans, (double)g->data_segs), 2));
    const char *k[] = {"Segmenty TCP", "Połączenia (przepływy TCP)", "Rozpoczęte przed zrzutem",
                       "Nawiązane", "Nieudane", "RTT uzgadniania", "Segmenty z danymi", "Retransmisje",
                       "Segmenty poza kolejnością", "Luki w numeracji", "Zduplikowane ACK",
                       "Ogłoszenia zerowego okna", "Segmenty keep-alive"};
    const char *v[] = {fmt_int(g->tcp_pkts_l4), fmt_int(A->tcp_flows), fmt_int(A->outcome[TO_MIDSTREAM]),
                       est, fail, rtt, fmt_int(g->data_segs), rtr, fmt_int(g->ooo), fmt_int(g->lost),
                       fmt_int(g->dupack), fmt_int(g->zerowin), fmt_int(g->keepalive)};
    doc_kv(d, k, v, 13);

    doc_h2(d, "Stany połączeń i flagi");
    doc_figure(d, A, FIG_TCP_STATES);
    doc_figure(d, A, FIG_TCP_FLAGS);
    doc_h2(d, "Opóźnienia i zdarzenia");
    if (A->nrtt) doc_figure(d, A, FIG_RTT);
    doc_figure(d, A, FIG_TCP_EVENTS);
    doc_h2(d, "Największe połączenia");
    flows_table(d, A, 1);
}

static void sec_flows(doc_t *d, const analysis_t *A)
{
    doc_h1(d, "6. Charakterystyka przepływów");
    doc_text(d, "Przepływ to dwukierunkowa wymiana pakietów o tej samej 5-krotce (adresy IP, porty, "
                "protokół). Przepływ kończy się po zamknięciu połączenia TCP, ponownym użyciu "
                "5-krotki lub po okresie bezczynności dłuższym niż limit czasu. Wykresy dystrybuanty "
                "pokazują, jaki odsetek przepływów nie przekracza danej wielkości lub czasu trwania; "
                "typowy ruch sieciowy składa się z wielu krótkich przepływów i nielicznych dużych "
                "transferów.");
    doc_figure(d, A, FIG_FLOW_SIZE);
    doc_figure(d, A, FIG_FLOW_DUR);
    table_t t;
    table_init(&t, 6);
    table_col(&t, 0, "Protokół", 1, AL_LEFT);
    table_col(&t, 1, "Przepływy", 1, AL_RIGHT);
    table_col(&t, 2, "Mediana wielkości", 1.2, AL_RIGHT);
    table_col(&t, 3, "95. percentyl", 1.1, AL_RIGHT);
    table_col(&t, 4, "Maksimum", 1, AL_RIGHT);
    table_col(&t, 5, "Mediana czasu", 1.1, AL_RIGHT);
    for (int k = 0; k < 2; k++) {
        size_t n = A->nfsize[k];
        if (!n) continue;
        table_add(&t, k ? "UDP" : "TCP", fmt_int(n), fmt_bytes(quantile_sorted(A->fsize[k], n, 0.5)),
                  fmt_bytes(quantile_sorted(A->fsize[k], n, 0.95)), fmt_bytes(A->fsize[k][n - 1]),
                  A->nfdur[k] ? fmt_dur(quantile_sorted(A->fdur[k], A->nfdur[k], 0.5)) : "-");
    }
    doc_table(d, &t, "Statystyki przepływów");
    table_free(&t);
}

static void sec_udp(doc_t *d, const analysis_t *A)
{
    const global_t *g = &A->g;
    const dns_stats_t *s = &A->dns;
    doc_h1(d, "7. Analiza UDP i DNS");
    if (A->udp_flows == 0) {
        doc_text(d, "W zrzucie nie wykryto ruchu UDP.");
        return;
    }
    doc_text(d, "UDP nie ma mechanizmu połączeń, dlatego przepływy wyznaczane są na podstawie "
                "5-krotki i limitu bezczynności. Przepływy bez żadnej odpowiedzi są naturalne dla "
                "części protokołów (np. syslog, strumienie multimedialne), ale ich duży udział "
                "towarzyszy też skanowaniu i atakom wolumetrycznym.");
    char ow[96];
    snprintf(ow, sizeof ow, "%s (%s)", fmt_int(A->udp_oneway), fmt_pct(safe_div((double)A->udp_oneway, (double)A->udp_flows), 1));
    const char *k[] = {"Datagramy UDP", "Bajty UDP", "Przepływy UDP", "Przepływy bez odpowiedzi",
                       "Komunikaty ICMP \"cel nieosiągalny\"", "w tym \"port nieosiągalny\""};
    const char *v[] = {fmt_int(g->ip_pkts[PR_UDP]), fmt_bytes((double)g->ip_bytes[PR_UDP]), fmt_int(A->udp_flows),
                       ow, fmt_int(g->icmp_unreach), fmt_int(g->icmp_port_unreach)};
    doc_kv(d, k, v, 6);
    flows_table(d, A, 0);

    doc_h2(d, "DNS");
    if (s->queries + s->responses == 0) {
        doc_text(d, "Brak komunikatów DNS (UDP/53) w zrzucie.");
        return;
    }
    char rc[256], qt[512], lon[96];
    snprintf(rc, sizeof rc, "NOERROR %s · NXDOMAIN %s · SERVFAIL %s · REFUSED %s · inne %s",
             fmt_int(s->rcode[0]), fmt_int(s->rcode[3]), fmt_int(s->rcode[2]), fmt_int(s->rcode[5]),
             fmt_int(s->responses - s->rcode[0] - s->rcode[3] - s->rcode[2] - s->rcode[5]));
    qt[0] = '\0';
    for (int q = 0; q < DQ_COUNT; q++) {
        if (!s->qtype[q]) continue;
        size_t L = strlen(qt);
        snprintf(qt + L, sizeof qt - L, "%s%s %s", L ? " · " : "", dns_qtype_name(q), fmt_int(s->qtype[q]));
    }
    snprintf(lon, sizeof lon, "%s (najdłuższa nazwa: %s znaków)", fmt_int(s->suspicious),
             fmt_int(s->max_name_len));
    const char *k2[] = {"Zapytania", "Odpowiedzi", "Kody odpowiedzi", "Typy zapytań",
                        "Unikalne nazwy", "Nazwy o cechach tunelowania", "Nieprawidłowe komunikaty"};
    const char *v2[] = {fmt_int(s->queries), fmt_int(s->responses), rc, qt[0] ? qt : "-",
                        fmt_int(s->nnames), lon, fmt_int(s->malformed)};
    doc_kv(d, k2, v2, 7);
    doc_figure(d, A, FIG_DNS);
}

static void sec_anomalies(doc_t *d, const analysis_t *A)
{
    doc_h1(d, "8. Wykryte nieprawidłowości");
    char b[512];
    if (A->an.n == 0) {
        doc_text(d, "Przy zastosowanych progach (dodatek A) nie wykryto nieprawidłowości. Nie oznacza "
                    "to, że ruch jest bezpieczny - heurystyki obejmują tylko wybrane, typowe wzorce.");
        return;
    }
    snprintf(b, sizeof b, "Wykryto %zu nieprawidłowości: %d o wysokiej, %d o średniej i %d o niskiej "
                          "ważności. Wyniki są heurystyczne - każde zdarzenie należy zweryfikować w "
                          "kontekście sieci (np. autoryzowane skanowanie, testy obciążeniowe).",
             A->an.n, A->sev_count[SEV_HIGH], A->sev_count[SEV_MEDIUM], A->sev_count[SEV_LOW]);
    doc_text(d, b);

    table_t t;
    table_init(&t, 4);
    table_col(&t, 0, "Ważność", 0.75, AL_LEFT);
    table_col(&t, 1, "Rodzaj", 1.5, AL_LEFT);
    table_col(&t, 2, "Opis", 3.3, AL_LEFT);
    table_col(&t, 3, "Czas od początku", 1.4, AL_LEFT);
    t.badge_col = 0;
    for (size_t i = 0; i < A->an.n; i++) {
        const anomaly_t *a = &A->an.v[i];
        char tm[96] = "-";
        if (a->t0 >= 0) snprintf(tm, sizeof tm, "%s - %s", fmt_dur(a->t0), fmt_dur(a->t1));
        table_add(&t, sev_name(a->sev), anomaly_type_name(a->type), a->title, tm);
        table_set_sev(&t, a->sev);
    }
    doc_table(d, &t, "Zestawienie nieprawidłowości");
    table_free(&t);

    if (figure_available(A, FIG_ANOMALIES)) doc_figure(d, A, FIG_ANOMALIES);

    doc_h2(d, "Szczegóły");
    size_t lim = A->an.n < 80 ? A->an.n : 80;
    for (size_t i = 0; i < lim; i++) {
        const anomaly_t *a = &A->an.v[i];
        double w = doc_width(d);
        double hdet = doc_wrap(d, 0, 0, w, a->detail, 9, 0, C_INK, 12.8, 0);
        doc_ensure(d, 40 + (hdet < 60 ? hdet : 60));
        double bw = doc_badge(d->cr, d->ml, d->y + 11, a->sev, 7);
        char tb[256];
        snprintf(tb, sizeof tb, "%zu. %s", i + 1, a->title);
        char fit[256];
        txt_fit(d->cr, tb, 10, 1, w - bw - 8, fit, sizeof fit);
        txt_draw(d->cr, d->ml + bw + 8, d->y + 11, fit, 10, 1, C_INK, AL_LEFT);
        d->y += 17;
        char meta[320];
        int n = snprintf(meta, sizeof meta, "%s · kod %s", anomaly_type_name(a->type), anomaly_type_code(a->type));
        if (a->t0 >= 0)
            n += snprintf(meta + n, sizeof meta - (size_t)n, " · czas %s - %s (%s - %s)", fmt_dur(a->t0),
                          fmt_dur(a->t1), fmt_utc(A->t0_ns + (int64_t)(a->t0 * 1e9)),
                          fmt_utc(A->t0_ns + (int64_t)(a->t1 * 1e9)));
        if (a->src.v && (size_t)n < sizeof meta)
            n += snprintf(meta + n, sizeof meta - (size_t)n, " · źródło %s", ip_str(&a->src));
        if (a->dst.v && (size_t)n < sizeof meta)
            snprintf(meta + n, sizeof meta - (size_t)n, " · cel %s", ip_str(&a->dst));
        doc_par(d, meta, 7.5, C_MUTED);
        d->y -= 2;
        doc_par(d, a->detail, 9, C_INK);
        d->y += 4;
    }
    if (lim < A->an.n) {
        snprintf(b, sizeof b, "Pominięto %zu dalszych pozycji o niższej ważności - pełna lista znajduje "
                              "się w pliku anomalie.csv.", A->an.n - lim);
        doc_note(d, b);
    }
}

static void sec_method(doc_t *d, const analysis_t *A)
{
    const config_t *c = A->cfg;
    doc_h1(d, "A. Metodyka i progi detekcji");
    doc_h2(d, "Przetwarzanie");
    doc_text(d, "Pliki pcap i pcapng odczytywane są przez bibliotekę libpcap z precyzją "
                "nanosekundową. Dekoder obsługuje Ethernet (w tym znaczniki VLAN 802.1Q/802.1ad, "
                "PPPoE, MPLS), Linux cooked capture (SLL, SLL2), surowe IP i interfejsy pętli "
                "zwrotnej, a w warstwie sieciowej IPv4 i IPv6 z nagłówkami rozszerzeń. Wszystkie "
                "pola odczytywane są z kontrolą granic, więc uszkodzone lub obcięte pakiety są "
                "zliczane, a nie przerywają analizy.");
    doc_text(d, "Pakiety TCP i UDP przypisywane są do przepływów w tablicy haszującej. Stroną "
                "inicjującą (klientem) jest nadawca segmentu SYN; gdy uzgodnienie nie zostało "
                "przechwycone, klient wyznaczany jest heurystyką portów dobrze znanych. Segment, "
                "którego numer sekwencyjny jest niższy od najwyższego dotychczas widzianego, "
                "uznawany jest za retransmisję, chyba że nadszedł w czasie krótszym niż RTT "
                "(maks. 3 ms) od poprzedniego - wtedy jest to zamiana kolejności. Numer wyższy od "
                "oczekiwanego oznacza lukę (segment utracony przed punktem przechwytywania).");
    doc_text(d, "Skoki natężenia ruchu wykrywane są odporną metodą statystyczną: przedział jest "
                "zaznaczany, gdy liczba pakietów na sekundę przekracza medianę o k-krotność "
                "znormalizowanego odchylenia bezwzględnego od mediany (MAD), jest co najmniej "
                "trzykrotnie wyższa od mediany i zawiera ponad 50 pakietów nadmiarowych. Mediana i "
                "MAD, w przeciwieństwie do średniej i odchylenia standardowego, nie są zaburzane "
                "przez same skoki.");

    doc_h2(d, "Progi detekcji");
    table_t t;
    table_init(&t, 3);
    table_col(&t, 0, "Detektor", 1.5, AL_LEFT);
    table_col(&t, 1, "Kryterium", 3.6, AL_LEFT);
    table_col(&t, 2, "Opcja", 1.1, AL_LEFT);
    char b[512];
    snprintf(b, sizeof b, ">= %d portów jednego hosta, >= 50%% zamkniętych/bez odpowiedzi", c->scan_ports);
    table_add(&t, "Skanowanie portów TCP/UDP", b, "--scan-ports");
    snprintf(b, sizeof b, ">= %d hostów na jednym porcie, >= 50%% bez odpowiedzi", c->scan_hosts);
    table_add(&t, "Przeszukiwanie hostów", b, "--scan-hosts");
    snprintf(b, sizeof b, ">= %d nieudanych SYN do jednej usługi, >= 50%% prób", c->synflood_min);
    table_add(&t, "SYN flood", b, "--syn-flood");
    snprintf(b, sizeof b, ">= %s pak./s do hosta, < 10%% odpowiedzi", fmt_num(c->udpflood_pps, 0));
    table_add(&t, "Zalew UDP", b, "--udp-flood");
    snprintf(b, sizeof b, "pak./s > mediana + %s * MAD, >= 3x mediana", fmt_num(c->spike_k, 1));
    table_add(&t, "Skok natężenia", b, "--spike-k");
    table_add(&t, "Nieprawidłowe flagi TCP", ">= 5 segmentów NULL/FIN/XMAS/SYN+FIN/SYN+RST od hosta", "-");
    snprintf(b, sizeof b, "retransmisje >= %s segmentów z danymi (min. 20)", fmt_pct(c->retrans_warn, 1));
    table_add(&t, "Retransmisje TCP", b, "--retrans");
    snprintf(b, sizeof b, ">= %d segmentów RST, >= 20%% segmentów TCP hosta", c->rst_min);
    table_add(&t, "Nadmiar RST", b, "--rst");
    snprintf(b, sizeof b, ">= %d zapytań z etykietą >= 30 znaków i entropią >= 3,5 bit/znak", c->dns_tunnel_min);
    table_add(&t, "Tunelowanie DNS", b, "--dns-tunnel");
    snprintf(b, sizeof b, ">= %d odpowiedzi NXDOMAIN, >= 50%% odpowiedzi klienta", c->nxdomain_min);
    table_add(&t, "NXDOMAIN (DGA)", b, "--nxdomain");
    table_add(&t, "Inne", "zerowe okno TCP, pakiety LAND, uszkodzone nagłówki, >= 50 ICMP "
                          "\"nieosiągalny\", protokoły nieszyfrowane (telnet, FTP, POP3, IMAP, TFTP, SNMP)", "-");
    snprintf(b, sizeof b, "przedział %s, limit bezczynności przepływu %s", fmt_dur(A->ts.bin), fmt_dur(c->flow_timeout));
    table_add(&t, "Parametry analizy", b, "--bin, --flow-timeout");
    doc_table(d, &t, "Progi użyte w tej analizie");
    table_free(&t);

    doc_h2(d, "Ograniczenia");
    doc_bullet(d, "Analiza opiera się wyłącznie na nagłówkach; zawartość ruchu szyfrowanego (TLS, QUIC) "
                  "nie jest badana.");
    doc_bullet(d, "Fragmenty IP nie są składane - kolejne fragmenty liczone są w statystykach "
                  "protokołów, ale nie są przypisywane do przepływów.");
    doc_bullet(d, "Wykrywanie retransmisji nie uwzględnia opcji SACK, a wyniki zależą od miejsca "
                  "przechwytywania (straty przed punktem pomiaru widoczne są jako luki).");
    doc_bullet(d, "Wykrywanie nieprawidłowości jest heurystyczne: możliwe są fałszywe alarmy "
                  "(np. autoryzowane skanery, systemy monitoringu) i przeoczenia ataków o niskim "
                  "natężeniu.");
}

static void sec_outputs(doc_t *d, const analysis_t *A)
{
    const config_t *c = A->cfg;
    doc_h2(d, "Pliki wynikowe");
    table_t t;
    table_init(&t, 2);
    table_col(&t, 0, "Plik", 1.6, AL_LEFT);
    table_col(&t, 1, "Zawartość", 4, AL_LEFT);
    table_add(&t, "raport.pdf", "niniejszy raport");
    if (c->write_png)
        for (int id = 0; id < FIG_COUNT; id++)
            if (figure_available(A, id)) {
                char f[96];
                snprintf(f, sizeof f, "wykresy/%s", figure_file(id));
                table_add(&t, f, figure_title(id));
            }
    if (c->write_csv) {
        table_add(&t, "przeplywy.csv", "wszystkie przepływy TCP/UDP z metrykami (CSV)");
        table_add(&t, "anomalie.csv", "wykryte nieprawidłowości (CSV)");
        table_add(&t, "podsumowanie.txt", "kluczowe wartości w formacie klucz=wartość");
    }
    doc_table(d, &t, "Pliki wygenerowane w katalogu wyjściowym");
    table_free(&t);
}

/* ------------------------------------------------------------------ */

static void build(doc_t *d, const analysis_t *A, const char *files, const char *gen)
{
    cover(d, A, files, gen);
    doc_new_page(d, 1);
    doc_toc(d);
    sec_input(d, A);
    sec_general(d, A);
    sec_time(d, A);
    sec_hosts(d, A);
    sec_tcp(d, A);
    sec_flows(d, A);
    sec_udp(d, A);
    sec_anomalies(d, A);
    sec_method(d, A);
    sec_outputs(d, A);
}

static void setup(doc_t *d, const analysis_t *A, const char *files, const char *gen)
{
    snprintf(d->head_left, sizeof d->head_left, "%s", A->cfg->title);
    snprintf(d->head_right, sizeof d->head_right, "%s", files);
    snprintf(d->foot_left, sizeof d->foot_left, "%s %s · wygenerowano %s", PA_NAME, PA_VERSION, gen);
}

int report_write_pdf(const analysis_t *A, const char *path)
{
    chart_set_font(A->cfg->font);
    char files[1024] = "";
    for (int i = 0; i < A->nfiles; i++) {
        size_t L = strlen(files);
        snprintf(files + L, sizeof files - L, "%s%s", i ? ", " : "", basename_of(A->files[i].path));
    }
    char gen[64];
    long long ts = report_timestamp();
    snprintf(gen, sizeof gen, "%s", fmt_utc((int64_t)ts * 1000000000LL));
    char *dot = strchr(gen, '.');                    /* bez milisekund */
    if (dot) memmove(dot, dot + 4, strlen(dot + 4) + 1);

    static doc_t dry, real;                          /* za duże na stos */
    memset(&dry, 0, sizeof dry);
    setup(&dry, A, files, gen);
    if (doc_begin(&dry, NULL, A->cfg->title, PA_NAME) != 0) return -1;
    build(&dry, A, files, gen);
    int pages = doc_end(&dry);
    if (pages < 0) return -1;

    memset(&real, 0, sizeof real);
    setup(&real, A, files, gen);
    real.total_pages = pages;
    real.toc_ref = dry.toc;
    real.ntoc_ref = dry.ntoc;
    if (doc_begin(&real, path, A->cfg->title, PA_NAME) != 0) return -1;
    build(&real, A, files, gen);
    int n = doc_end(&real);
    if (n >= 0 && n != pages) pa_warn("niespójny skład raportu (%d/%d stron)", n, pages);
    return n;
}
