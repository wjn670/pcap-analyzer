#ifndef PA_CONFIG_H
#define PA_CONFIG_H

typedef struct {
    const char *outdir;
    const char *title;
    const char *font;            /* nazwa dla fontconfig */
    int    top_n;
    double bin_width;            /* szerokość przedziału szeregów czasowych [s], 0 = auto */
    double flow_timeout;         /* czas bezczynności kończący przepływ [s] */

    /* progi detektorów */
    int    scan_ports;           /* skan pionowy: min. liczba portów jednego hosta */
    int    scan_hosts;           /* skan poziomy: min. liczba hostów na jednym porcie */
    int    synflood_min;         /* SYN flood: min. nieudanych prób do jednej usługi */
    double udpflood_pps;         /* zalew UDP: min. średnia liczba pakietów/s */
    double spike_k;              /* skok ruchu: mnożnik odporny (mediana + k*MAD) */
    int    dns_tunnel_min;       /* tunelowanie DNS: min. podejrzanych zapytań klienta */
    int    nxdomain_min;         /* DGA: min. odpowiedzi NXDOMAIN dla klienta */
    double retrans_warn;         /* odsetek retransmisji uznawany za problem */
    int    rst_min;              /* min. liczba segmentów RST wysłanych przez host */

    int    write_png, write_pdf, write_csv;
    int    quiet, verbose;
} config_t;

static inline void config_defaults(config_t *c)
{
    c->outdir = "raport";
    c->title = "Raport analizy ruchu TCP/UDP";
    c->font = "sans-serif";
    c->top_n = 10;
    c->bin_width = 0;
    c->flow_timeout = 120.0;
    c->scan_ports = 15;
    c->scan_hosts = 10;
    c->synflood_min = 200;
    c->udpflood_pps = 1000.0;
    c->spike_k = 6.0;
    c->dns_tunnel_min = 10;
    c->nxdomain_min = 20;
    c->retrans_warn = 0.02;
    c->rst_min = 100;
    c->write_png = c->write_pdf = c->write_csv = 1;
    c->quiet = c->verbose = 0;
}

#endif
