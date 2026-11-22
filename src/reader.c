#include "reader.h"
#include "util.h"

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pcap_t *open_file(input_file_t *f)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    /* Precyzja nanosekundowa: libpcap przelicza znaczniki z plików
     * mikrosekundowych, a pliki nanosekundowe nie tracą dokładności. */
    pcap_t *h = pcap_open_offline_with_tstamp_precision(f->path, PCAP_TSTAMP_PRECISION_NANO, errbuf);
    if (!h) {
        snprintf(f->err, sizeof f->err, "%s", errbuf);
        f->ok = 0;
    }
    return h;
}

static int64_t ts_ns(const struct pcap_pkthdr *h)
{
    /* przy PCAP_TSTAMP_PRECISION_NANO pole tv_usec zawiera nanosekundy */
    return (int64_t)h->ts.tv_sec * 1000000000LL + (int64_t)h->ts.tv_usec;
}

int reader_scan(input_file_t *f)
{
    f->ok = 1;
    f->err[0] = '\0';
    pcap_t *h = open_file(f);
    if (!h) return -1;

    f->dlt = pcap_datalink(h);
    const char *n = pcap_datalink_val_to_name(f->dlt);
    snprintf(f->dlt_name, sizeof f->dlt_name, "%s (%d)", n ? n : "?", f->dlt);
    f->snaplen = (uint32_t)pcap_snapshot(h);
    f->packets = f->bytes = f->cap_bytes = 0;
    f->first_ns = INT64_MAX;
    f->last_ns = INT64_MIN;
    f->unordered = 0;

    struct pcap_pkthdr *hdr;
    const u_char *data;
    int rc;
    int64_t prev = INT64_MIN;
    while ((rc = pcap_next_ex(h, &hdr, &data)) == 1) {
        int64_t t = ts_ns(hdr);
        if (t < f->first_ns) f->first_ns = t;
        if (t > f->last_ns) f->last_ns = t;
        if (t < prev) f->unordered = 1;
        prev = t;
        f->packets++;
        f->bytes += hdr->len;
        f->cap_bytes += hdr->caplen;
    }
    if (rc == -1) {
        f->read_error = 1;
        snprintf(f->err, sizeof f->err, "%s", pcap_geterr(h));
    }
    if (f->packets == 0) f->first_ns = f->last_ns = 0;
    pcap_close(h);
    return 0;
}

typedef struct {
    pcap_t *h;
    struct pcap_pkthdr *hdr;
    const u_char *data;
    int64_t ts;
    int live;
} cursor_t;

static void cursor_advance(cursor_t *c, input_file_t *f)
{
    int rc = pcap_next_ex(c->h, &c->hdr, &c->data);
    if (rc == 1) {
        c->ts = ts_ns(c->hdr);
        return;
    }
    if (rc == -1 && !f->read_error) {
        f->read_error = 1;
        snprintf(f->err, sizeof f->err, "%s", pcap_geterr(c->h));
    }
    c->live = 0;
    pcap_close(c->h);
    c->h = NULL;
}

uint64_t reader_merge(input_file_t *files, int nfiles, reader_cb cb, void *ctx)
{
    cursor_t *cur = xcalloc((size_t)nfiles, sizeof *cur);
    int live = 0;
    for (int i = 0; i < nfiles; i++) {
        if (!files[i].ok || files[i].packets == 0) continue;
        cur[i].h = open_file(&files[i]);
        if (!cur[i].h) continue;
        cur[i].live = 1;
        cursor_advance(&cur[i], &files[i]);
        if (cur[i].live) live++;
    }

    uint64_t count = 0;
    while (live > 0) {
        /* wybór pakietu o najwcześniejszym znaczniku czasu (k zwykle małe) */
        int best = -1;
        for (int i = 0; i < nfiles; i++)
            if (cur[i].live && (best < 0 || cur[i].ts < cur[best].ts)) best = i;
        cursor_t *c = &cur[best];
        cb(ctx, best, files[best].dlt, c->ts, c->hdr->caplen, c->hdr->len, c->data);
        count++;
        cursor_advance(c, &files[best]);
        if (!c->live) live--;
    }
    free(cur);
    return count;
}
