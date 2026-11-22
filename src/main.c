#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "analysis.h"
#include "chart.h"
#include "export.h"
#include "figures.h"
#include "reader.h"
#include "report.h"

static void usage(FILE *o)
{
    fprintf(o,
        "Użycie: " PA_NAME " [opcje] plik.pcap [plik2.pcap ...]\n"
        "\n"
        "Analizuje komunikację TCP i UDP w plikach pcap/pcapng i tworzy raport PDF,\n"
        "wykresy PNG oraz pliki CSV.\n"
        "\n"
        "Opcje ogólne:\n"
        "  -o, --output KATALOG     katalog wyjściowy (domyślnie: raport)\n"
        "  -t, --title TEKST        tytuł raportu\n"
        "  -n, --top N              długość rankingów (domyślnie 10)\n"
        "  -b, --bin SEKUNDY        szerokość przedziału czasu (domyślnie automatycznie)\n"
        "      --flow-timeout S     limit bezczynności przepływu (domyślnie 120 s)\n"
        "      --font RODZINA       czcionka raportu (domyślnie sans-serif)\n"
        "      --no-pdf, --no-png, --no-csv   pomiń dany rodzaj wyników\n"
        "  -q, --quiet              bez podsumowania na wyjściu standardowym\n"
        "  -h, --help               ta pomoc\n"
        "  -V, --version            wersja programu\n"
        "\n"
        "Progi detekcji nieprawidłowości:\n"
        "      --scan-ports N       skanowanie portów: min. liczba portów (15)\n"
        "      --scan-hosts N       przeszukiwanie hostów: min. liczba hostów (10)\n"
        "      --syn-flood N        SYN flood: min. nieudanych prób do usługi (200)\n"
        "      --udp-flood PPS      zalew UDP: min. pakietów/s do hosta (1000)\n"
        "      --spike-k K          skok ruchu: mnożnik MAD (6)\n"
        "      --retrans FRAKCJA    próg odsetka retransmisji TCP (0.02)\n"
        "      --rst N              nadmiar RST: min. segmentów od hosta (100)\n"
        "      --dns-tunnel N       tunelowanie DNS: min. podejrzanych zapytań (10)\n"
        "      --nxdomain N         DGA: min. odpowiedzi NXDOMAIN dla klienta (20)\n");
}

static double num_arg(const char *s, const char *opt, double lo, double hi)
{
    char *end;
    errno = 0;
    double v = strtod(s, &end);
    if (errno || end == s || *end || v < lo || v > hi)
        die("nieprawidłowa wartość opcji %s: '%s' (zakres %g-%g)", opt, s, lo, hi);
    return v;
}

static void mkdir_p(const char *path)
{
    char buf[4096];
    snprintf(buf, sizeof buf, "%s", path);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(buf, 0755) != 0 && errno != EEXIST) die("nie można utworzyć katalogu %s: %s", buf, strerror(errno));
        *p = '/';
    }
    if (mkdir(buf, 0755) != 0 && errno != EEXIST) die("nie można utworzyć katalogu %s: %s", buf, strerror(errno));
}

enum {
    OPT_TIMEOUT = 1000, OPT_FONT, OPT_NOPDF, OPT_NOPNG, OPT_NOCSV, OPT_SCANP, OPT_SCANH,
    OPT_SYN, OPT_UDP, OPT_SPIKE, OPT_RETR, OPT_RST, OPT_DNS, OPT_NX
};

int main(int argc, char **argv)
{
    config_t cfg;
    config_defaults(&cfg);
    static const struct option opts[] = {
        {"output", required_argument, 0, 'o'}, {"title", required_argument, 0, 't'},
        {"top", required_argument, 0, 'n'}, {"bin", required_argument, 0, 'b'},
        {"flow-timeout", required_argument, 0, OPT_TIMEOUT}, {"font", required_argument, 0, OPT_FONT},
        {"no-pdf", no_argument, 0, OPT_NOPDF}, {"no-png", no_argument, 0, OPT_NOPNG},
        {"no-csv", no_argument, 0, OPT_NOCSV}, {"scan-ports", required_argument, 0, OPT_SCANP},
        {"scan-hosts", required_argument, 0, OPT_SCANH}, {"syn-flood", required_argument, 0, OPT_SYN},
        {"udp-flood", required_argument, 0, OPT_UDP}, {"spike-k", required_argument, 0, OPT_SPIKE},
        {"retrans", required_argument, 0, OPT_RETR}, {"rst", required_argument, 0, OPT_RST},
        {"dns-tunnel", required_argument, 0, OPT_DNS}, {"nxdomain", required_argument, 0, OPT_NX},
        {"quiet", no_argument, 0, 'q'}, {"help", no_argument, 0, 'h'}, {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0}};
    int c;
    while ((c = getopt_long(argc, argv, "o:t:n:b:qhV", opts, NULL)) != -1) {
        switch (c) {
        case 'o': cfg.outdir = optarg; break;
        case 't': cfg.title = optarg; break;
        case 'n': cfg.top_n = (int)num_arg(optarg, "--top", 1, 50); break;
        case 'b': cfg.bin_width = num_arg(optarg, "--bin", 0.001, 86400); break;
        case OPT_TIMEOUT: cfg.flow_timeout = num_arg(optarg, "--flow-timeout", 1, 86400); break;
        case OPT_FONT: cfg.font = optarg; break;
        case OPT_NOPDF: cfg.write_pdf = 0; break;
        case OPT_NOPNG: cfg.write_png = 0; break;
        case OPT_NOCSV: cfg.write_csv = 0; break;
        case OPT_SCANP: cfg.scan_ports = (int)num_arg(optarg, "--scan-ports", 2, 65535); break;
        case OPT_SCANH: cfg.scan_hosts = (int)num_arg(optarg, "--scan-hosts", 2, 1e7); break;
        case OPT_SYN: cfg.synflood_min = (int)num_arg(optarg, "--syn-flood", 1, 1e9); break;
        case OPT_UDP: cfg.udpflood_pps = num_arg(optarg, "--udp-flood", 1, 1e9); break;
        case OPT_SPIKE: cfg.spike_k = num_arg(optarg, "--spike-k", 1, 100); break;
        case OPT_RETR: cfg.retrans_warn = num_arg(optarg, "--retrans", 0.0001, 1); break;
        case OPT_RST: cfg.rst_min = (int)num_arg(optarg, "--rst", 1, 1e9); break;
        case OPT_DNS: cfg.dns_tunnel_min = (int)num_arg(optarg, "--dns-tunnel", 1, 1e9); break;
        case OPT_NX: cfg.nxdomain_min = (int)num_arg(optarg, "--nxdomain", 1, 1e9); break;
        case 'q': cfg.quiet = 1; break;
        case 'h': usage(stdout); return 0;
        case 'V': printf(PA_NAME " " PA_VERSION "\n"); return 0;
        default: usage(stderr); return 2;
        }
    }
    int nfiles = argc - optind;
    if (nfiles < 1) {
        usage(stderr);
        return 2;
    }

    /* przebieg 1: metadane plików */
    input_file_t *files = xcalloc((size_t)nfiles, sizeof *files);
    int64_t t0 = INT64_MAX, t1 = INT64_MIN;
    uint64_t total = 0;
    for (int i = 0; i < nfiles; i++) {
        files[i].path = argv[optind + i];
        if (reader_scan(&files[i]) != 0) {
            pa_warn("pominięto %s: %s", files[i].path, files[i].err);
            continue;
        }
        if (files[i].read_error) pa_warn("%s: plik uszkodzony lub ucięty (%s)", files[i].path, files[i].err);
        if (files[i].packets == 0) continue;
        total += files[i].packets;
        if (files[i].first_ns < t0) t0 = files[i].first_ns;
        if (files[i].last_ns > t1) t1 = files[i].last_ns;
    }
    if (total == 0) die("brak pakietów do analizy");

    /* przebieg 2: analiza */
    static analysis_t A;
    analysis_init(&A, &cfg, files, nfiles, t0, t1);
    reader_merge(files, nfiles, analysis_packet, &A);
    analysis_finish(&A);
    anomaly_detect(&A);

    /* wyniki */
    mkdir_p(cfg.outdir);
    char path[4096];
    chart_set_font(cfg.font);
    int npng = 0, pages = 0;
    if (cfg.write_png) {
        snprintf(path, sizeof path, "%s/wykresy", cfg.outdir);
        mkdir_p(path);
        npng = figures_write_png(&A, path);
        if (npng < 0) die("błąd zapisu wykresów PNG");
    }
    if (cfg.write_csv) {
        snprintf(path, sizeof path, "%s/przeplywy.csv", cfg.outdir);
        if (export_flows_csv(&A, path)) die("nie można zapisać %s", path);
        snprintf(path, sizeof path, "%s/anomalie.csv", cfg.outdir);
        if (export_anomalies_csv(&A, path)) die("nie można zapisać %s", path);
        snprintf(path, sizeof path, "%s/podsumowanie.txt", cfg.outdir);
        if (export_summary(&A, path)) die("nie można zapisać %s", path);
    }
    if (cfg.write_pdf) {
        snprintf(path, sizeof path, "%s/raport.pdf", cfg.outdir);
        pages = report_write_pdf(&A, path);
        if (pages < 0) die("nie można zapisać raportu %s", path);
    }

    if (!cfg.quiet) {
        const global_t *g = &A.g;
        printf("%s %s - analiza %d plik%s: %s pakietów, %s\n", PA_NAME, PA_VERSION, nfiles,
               nfiles == 1 ? "u" : "ów", fmt_int(g->pkts), fmt_bytes((double)g->bytes));
        printf("Okres:      %s - %s (%s)\n", fmt_utc(A.t0_ns), fmt_utc(A.t1_ns), fmt_dur(A.duration));
        printf("Protokoły:  TCP %s, UDP %s, ICMP %s, inne %s (udział bajtów)\n",
               fmt_pct((double)g->ip_bytes[PR_TCP] / g->bytes, 1), fmt_pct((double)g->ip_bytes[PR_UDP] / g->bytes, 1),
               fmt_pct((double)g->ip_bytes[PR_ICMP] / g->bytes, 1),
               fmt_pct((double)(g->bytes - g->ip_bytes[PR_TCP] - g->ip_bytes[PR_UDP] - g->ip_bytes[PR_ICMP]) / g->bytes, 1));
        printf("Przepływy:  TCP %s, UDP %s; hosty: %s\n", fmt_int(A.tcp_flows), fmt_int(A.udp_flows), fmt_int(A.nhosts));
        printf("Nieprawidłowości: %zu (wysokie %d, średnie %d, niskie %d)\n", A.an.n,
               A.sev_count[SEV_HIGH], A.sev_count[SEV_MEDIUM], A.sev_count[SEV_LOW]);
        for (size_t i = 0; i < A.an.n && i < 15; i++)
            printf("  [%-6s] %s\n", sev_name(A.an.v[i].sev), A.an.v[i].title);
        if (A.an.n > 15) printf("  ... i %zu kolejnych (anomalie.csv)\n", A.an.n - 15);
        printf("Wyniki:     %s/", cfg.outdir);
        if (cfg.write_pdf) printf(" raport.pdf (%d str.)", pages);
        if (cfg.write_png) printf(" wykresy/ (%d PNG)", npng);
        if (cfg.write_csv) printf(" przeplywy.csv anomalie.csv podsumowanie.txt");
        printf("\n");
    }
    analysis_free(&A);
    free(files);
    return 0;
}
