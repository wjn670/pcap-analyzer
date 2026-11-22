/* W plikach CSV liczby mają kropkę dziesiętną, żeby dało się je łatwo wczytać. */
#include "export.h"

#include <stdio.h>
#include <string.h>

static void csv_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s; s++) {
        if (*s == '"') fputc('"', f);
        fputc(*s, f);
    }
    fputc('"', f);
}

int export_flows_csv(const analysis_t *A, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "proto,client,client_port,server,server_port,service,start_s,end_s,duration_s,"
               "pkts_c2s,pkts_s2c,bytes_c2s,bytes_s2c,payload_c2s,payload_s2c,state,rtt_ms,"
               "retrans,out_of_order,lost,dup_ack,zero_window,icmp_unreach\n");
    for (size_t i = 0; i < A->ft.n; i++) {
        const flow_t *fl = &A->ft.v[i];
        const char *svc = port_service(fl->proto, fl->sport);
        fprintf(f, "%s,%s,%u,", fl->proto == IPP_TCP ? "TCP" : "UDP", ip_str(&fl->cli), fl->cport);
        fprintf(f, "%s,%u,%s,", ip_str(&fl->srv), fl->sport, svc ? svc : "");
        fprintf(f, "%.6f,%.6f,%.6f,", fl->first, fl->last, fl->last - fl->first);
        fprintf(f, "%llu,%llu,%llu,%llu,%llu,%llu,", (unsigned long long)fl->d[0].pkts,
                (unsigned long long)fl->d[1].pkts, (unsigned long long)fl->d[0].bytes,
                (unsigned long long)fl->d[1].bytes, (unsigned long long)fl->d[0].payload,
                (unsigned long long)fl->d[1].payload);
        csv_str(f, fl->proto == IPP_TCP ? tcp_outcome_name(fl->outcome) : "");
        if (fl->rtt > 0) fprintf(f, ",%.3f,", fl->rtt * 1000.0);
        else fprintf(f, ",,");
        fprintf(f, "%u,%u,%u,%u,%u,%u\n", fl->d[0].retrans + fl->d[1].retrans, fl->d[0].ooo + fl->d[1].ooo,
                fl->d[0].lost + fl->d[1].lost, fl->d[0].dupack + fl->d[1].dupack,
                fl->d[0].zerowin + fl->d[1].zerowin, fl->icmp_unreach);
    }
    return fclose(f) == 0 ? 0 : -1;
}

int export_anomalies_csv(const analysis_t *A, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "severity,type,title,start_s,end_s,src,dst,detail\n");
    for (size_t i = 0; i < A->an.n; i++) {
        const anomaly_t *a = &A->an.v[i];
        fprintf(f, "%s,%s,", sev_name(a->sev), anomaly_type_code(a->type));
        csv_str(f, a->title);
        if (a->t0 >= 0) fprintf(f, ",%.3f,%.3f,", a->t0, a->t1);
        else fprintf(f, ",,,");
        fprintf(f, "%s,%s,", a->src.v ? ip_str(&a->src) : "", a->dst.v ? ip_str(&a->dst) : "");
        csv_str(f, a->detail);
        fputc('\n', f);
    }
    return fclose(f) == 0 ? 0 : -1;
}

int export_summary(const analysis_t *A, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    const global_t *g = &A->g;
#define KV(k, v) fprintf(f, "%s=%llu\n", k, (unsigned long long)(v))
    KV("files", A->nfiles);
    KV("packets", g->pkts);
    KV("bytes", g->bytes);
    fprintf(f, "duration_s=%.6f\n", A->duration);
    KV("ipv4", g->ipv4);
    KV("ipv6", g->ipv6);
    KV("non_ip", g->nonip);
    KV("truncated", g->trunc);
    KV("malformed", g->malformed + g->l4_bad);
    KV("fragments", g->fragments);
    KV("vlan", g->vlan);
    KV("tcp_packets", g->ip_pkts[PR_TCP]);
    KV("udp_packets", g->ip_pkts[PR_UDP]);
    KV("icmp_packets", g->ip_pkts[PR_ICMP]);
    KV("other_ip_packets", g->ip_pkts[PR_OTHER]);
    KV("hosts", A->nhosts);
    KV("tcp_flows", A->tcp_flows);
    KV("udp_flows", A->udp_flows);
    static const char *const oc[TO_COUNT] = {"none", "unanswered", "rejected", "half_open", "open",
                                             "closed", "half_closed", "reset", "midstream"};
    for (int o = 1; o < TO_COUNT; o++) fprintf(f, "tcp_state_%s=%llu\n", oc[o], (unsigned long long)A->outcome[o]);
    if (A->nrtt) fprintf(f, "rtt_median_ms=%.3f\n", quantile_sorted(A->rtt, A->nrtt, 0.5) * 1000);
    KV("tcp_data_segments", g->data_segs);
    KV("tcp_retransmissions", g->retrans);
    KV("tcp_out_of_order", g->ooo);
    KV("tcp_dup_ack", g->dupack);
    KV("tcp_zero_window", g->zerowin);
    KV("dns_queries", A->dns.queries);
    KV("dns_responses", A->dns.responses);
    KV("dns_nxdomain", A->dns.rcode[3]);
    KV("anomalies", A->an.n);
    KV("anomalies_high", A->sev_count[SEV_HIGH]);
    KV("anomalies_medium", A->sev_count[SEV_MEDIUM]);
    KV("anomalies_low", A->sev_count[SEV_LOW]);
    for (size_t i = 0; i < A->an.n; i++)
        fprintf(f, "anomaly=%s;%s;%s\n", anomaly_type_code(A->an.v[i].type), sev_name(A->an.v[i].sev),
                A->an.v[i].title);
#undef KV
    return fclose(f) == 0 ? 0 : -1;
}
