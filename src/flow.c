/*
 * Tablica haszująca trzyma indeksy aktywnych przepływów z ft->v. Zakończony
 * przepływ zostaje w wektorze, ale wypada z łańcucha, więc następny pakiet
 * z tą samą 5-krotką zaczyna nowy przepływ.
 */
#include "flow.h"

#include <stdlib.h>
#include <string.h>

#define INITIAL_BUCKETS 4096u

static uint64_t tuple_hash(const ipaddr_t *a, uint16_t ap, const ipaddr_t *b, uint16_t bp, uint8_t proto)
{
    struct {
        uint8_t a1[16], a2[16];
        uint16_t p1, p2;
        uint8_t v, proto, pad[2];
    } k;
    memset(&k, 0, sizeof k);
    int c = ip_cmp(a, b);
    if (c > 0 || (c == 0 && ap > bp)) {       /* normalizacja kierunku */
        const ipaddr_t *t = a; a = b; b = t;
        uint16_t tp = ap; ap = bp; bp = tp;
    }
    memcpy(k.a1, a->a, 16);
    memcpy(k.a2, b->a, 16);
    k.p1 = ap;
    k.p2 = bp;
    k.v = a->v;
    k.proto = proto;
    return hash64(&k, sizeof k, 0x5eed);
}

static int flow_match(const flow_t *f, const ipaddr_t *a, uint16_t ap,
                      const ipaddr_t *b, uint16_t bp, uint8_t proto)
{
    if (f->proto != proto) return 0;
    if (f->cport == ap && f->sport == bp && ip_eq(&f->cli, a) && ip_eq(&f->srv, b)) return 1;
    if (f->cport == bp && f->sport == ap && ip_eq(&f->cli, b) && ip_eq(&f->srv, a)) return 1;
    return 0;
}

void flowtable_init(flowtable_t *ft)
{
    memset(ft, 0, sizeof *ft);
    ft->nbuckets = INITIAL_BUCKETS;
    ft->buckets = xmalloc(ft->nbuckets * sizeof *ft->buckets);
    for (size_t i = 0; i < ft->nbuckets; i++) ft->buckets[i] = -1;
}

void flowtable_free(flowtable_t *ft)
{
    free(ft->v);
    free(ft->buckets);
    memset(ft, 0, sizeof *ft);
}

static size_t bucket_of(const flowtable_t *ft, const flow_t *f)
{
    return (size_t)(tuple_hash(&f->cli, f->cport, &f->srv, f->sport, f->proto) & (ft->nbuckets - 1));
}

static void rehash(flowtable_t *ft)
{
    size_t nb = ft->nbuckets * 2;
    int32_t *b = xmalloc(nb * sizeof *b);
    for (size_t i = 0; i < nb; i++) b[i] = -1;
    free(ft->buckets);
    ft->buckets = b;
    ft->nbuckets = nb;
    for (size_t i = 0; i < ft->n; i++) {
        flow_t *f = &ft->v[i];
        if (!f->active) continue;
        size_t k = bucket_of(ft, f);
        f->next = ft->buckets[k];
        ft->buckets[k] = (int32_t)i;
    }
}

static void unlink_flow(flowtable_t *ft, int32_t idx)
{
    flow_t *f = &ft->v[idx];
    size_t k = bucket_of(ft, f);
    int32_t *pp = &ft->buckets[k];
    while (*pp >= 0) {
        if (*pp == idx) {
            *pp = f->next;
            break;
        }
        pp = &ft->v[*pp].next;
    }
    f->next = -1;
    ft->nactive--;
}

int32_t flow_lookup(const flowtable_t *ft, const ipaddr_t *a, uint16_t ap,
                    const ipaddr_t *b, uint16_t bp, uint8_t proto)
{
    size_t k = (size_t)(tuple_hash(a, ap, b, bp, proto) & (ft->nbuckets - 1));
    for (int32_t i = ft->buckets[k]; i >= 0; i = ft->v[i].next)
        if (flow_match(&ft->v[i], a, ap, b, bp, proto)) return i;
    return -1;
}

static void finish_flow(flow_t *f)
{
    f->active = 0;
    if (f->proto != IPP_TCP) {
        f->outcome = TO_NONE;
        return;
    }
    /* dane w obu kierunkach mimo nieprzechwyconego końca uzgadniania */
    if (!f->established && (f->syn_seen || f->synack_seen) &&
        f->d[0].payload > 0 && f->d[1].payload > 0)
        f->established = 1;

    if (!f->syn_seen && !f->synack_seen) {
        f->outcome = TO_MIDSTREAM;
        return;
    }
    if (!f->established) {
        if (f->synack_seen) f->outcome = TO_HALF_OPEN;
        else if (f->rejected) f->outcome = TO_REJECTED;
        else f->outcome = TO_UNANSWERED;
        return;
    }
    int fin0 = f->d[0].fin > 0, fin1 = f->d[1].fin > 0;
    int rst = f->d[0].rst > 0 || f->d[1].rst > 0;
    if (fin0 && fin1) f->outcome = TO_CLOSED;
    else if (rst) f->outcome = TO_RESET;
    else if (fin0 || fin1) f->outcome = TO_HALF_CLOSED;
    else f->outcome = TO_OPEN;
}

/* Czy nadawca pakietu otwierającego przepływ jest klientem. */
static int src_is_client(const packet_t *p)
{
    if (p->proto == IPP_TCP) {
        uint8_t f = p->tcp_flags & (TCPF_SYN | TCPF_ACK);
        if (f == TCPF_SYN) return 1;
        if (f == (TCPF_SYN | TCPF_ACK)) return 0;
    }
    int sw = port_is_wellknown(p->proto, p->sport);
    int dw = port_is_wellknown(p->proto, p->dport);
    if (dw && !sw) return 1;
    if (sw && !dw) return 0;
    if (p->proto == IPP_TCP) return p->dport <= p->sport; /* niższy port = usługa */
    return 1;                                             /* UDP: pierwszy nadawca */
}

/* Analiza segmentu TCP w kontekście przepływu. Zwraca maskę FEV_*. */
static int tcp_update(flow_t *f, int dir, const packet_t *p)
{
    flow_dir_t *d = &f->d[dir];
    flow_dir_t *o = &f->d[!dir];
    uint8_t fl = p->tcp_flags;
    int ev = 0;

    d->flags_or |= fl;
    if (fl & TCPF_SYN) d->syn++;
    if (fl & TCPF_FIN) d->fin++;
    if (fl & TCPF_RST) { d->rst++; ev |= FEV_RST; }

    /* --- uzgadnianie trójetapowe --- */
    uint8_t sa = fl & (TCPF_SYN | TCPF_ACK);
    if (sa == TCPF_SYN && dir == 0 && !(fl & TCPF_RST)) {
        if (!f->syn_seen) {
            f->syn_seen = 1;
            f->isn = p->seq;
            f->t_syn = p->ts;
            ev |= FEV_SYN;
        }
    } else if (sa == (TCPF_SYN | TCPF_ACK) && dir == 1) {
        f->synack_seen = 1;
    } else if (dir == 0 && (fl & TCPF_ACK) && !(fl & (TCPF_SYN | TCPF_RST)) &&
               f->synack_seen && !f->established) {
        f->established = 1;
        if (f->syn_seen) f->rtt = p->ts - f->t_syn;
    }
    if (dir == 1 && (fl & TCPF_RST) && f->syn_seen && !f->synack_seen && !f->established)
        f->rejected = 1;

    if (fl & TCPF_SYN) {
        if (p->mss) d->mss = p->mss;
        if (p->wscale >= 0) d->wscale = p->wscale;
    }

    /* --- numery sekwencyjne: retransmisje, luki, kolejność --- */
    uint32_t seglen = p->payload_len + ((fl & TCPF_SYN) ? 1u : 0u) + ((fl & TCPF_FIN) ? 1u : 0u);
    if (p->payload_len > 0) d->data_segs++;
    if (!(fl & TCPF_RST)) {
        if (!d->seq_init) {
            d->max_end = p->seq + seglen;
            d->seq_init = 1;
        } else if (seglen > 0) {
            int32_t diff = (int32_t)(p->seq - d->max_end);
            if (diff > 0) {
                d->lost++;
                ev |= FEV_LOST;
                d->max_end = p->seq + seglen;
            } else if (diff == 0) {
                d->max_end = p->seq + seglen;
            } else if (p->payload_len <= 1 && !(fl & (TCPF_SYN | TCPF_FIN)) &&
                       (int32_t)(p->seq + 1 - d->max_end) == 0) {
                d->keepalive++;
                ev |= FEV_KEEPALIVE;
            } else {
                /* segment z numerem poniżej oczekiwanego: retransmisja albo
                 * zamiana kolejności (krótki odstęp od poprzedniego segmentu) */
                double gap = p->ts - d->last_ts;
                double thr = (f->rtt > 0 && f->rtt < 0.003) ? f->rtt : 0.003;
                if (gap < thr && !(fl & TCPF_SYN)) {
                    d->ooo++;
                    ev |= FEV_OOO;
                } else {
                    d->retrans++;
                    ev |= FEV_RETRANS;
                }
                if ((int32_t)(p->seq + seglen - d->max_end) > 0) d->max_end = p->seq + seglen;
            }
        }
    }

    /* --- potwierdzenia i okno --- */
    if ((fl & TCPF_ACK) && !(fl & TCPF_RST)) {
        if (p->payload_len == 0 && !(fl & (TCPF_SYN | TCPF_FIN)) && d->ack_init &&
            p->ack == d->last_ack && p->win == d->last_win && p->win != 0 && o->seq_init) {
            d->dupack++;
            ev |= FEV_DUPACK;
        }
        d->last_ack = p->ack;
        d->last_win = p->win;
        d->ack_init = 1;
    }
    if (p->win == 0 && !(fl & (TCPF_RST | TCPF_SYN))) {
        d->zerowin++;
        ev |= FEV_ZEROWIN;
    }
    d->last_ts = p->ts;
    return ev;
}

int flow_update(flowtable_t *ft, const packet_t *p, double timeout, int32_t *idx_out, int *dir_out)
{
    *idx_out = -1;
    *dir_out = 0;
    if ((p->proto != IPP_TCP && p->proto != IPP_UDP) || !p->l4_ok) return 0;

    int ev = 0;
    int32_t idx = flow_lookup(ft, &p->src, p->sport, &p->dst, p->dport, p->proto);
    if (idx >= 0) {
        flow_t *f = &ft->v[idx];
        int end = 0;
        if (p->ts - f->last > timeout) {
            end = 1;
        } else if (p->proto == IPP_TCP && (p->tcp_flags & (TCPF_SYN | TCPF_ACK)) == TCPF_SYN) {
            int closed = (f->d[0].fin && f->d[1].fin) || f->d[0].rst || f->d[1].rst;
            int new_attempt = f->syn_seen && !f->synack_seen && p->seq != f->isn;
            if ((closed && (!f->syn_seen || p->seq != f->isn)) || new_attempt) end = 1;
        }
        if (end) {
            unlink_flow(ft, idx);
            finish_flow(f);
            idx = -1;
        }
    }

    if (idx < 0) {
        if (ft->nactive * 4 >= ft->nbuckets * 3) rehash(ft);
        if (ft->n == ft->cap) {
            ft->cap = ft->cap ? ft->cap * 2 : 1024;
            ft->v = xrealloc(ft->v, ft->cap * sizeof *ft->v);
        }
        idx = (int32_t)ft->n++;
        flow_t *f = &ft->v[idx];
        memset(f, 0, sizeof *f);
        if (src_is_client(p)) {
            f->cli = p->src; f->cport = p->sport;
            f->srv = p->dst; f->sport = p->dport;
        } else {
            f->cli = p->dst; f->cport = p->dport;
            f->srv = p->src; f->sport = p->sport;
        }
        f->proto = p->proto;
        f->first = f->last = p->ts;
        f->rtt = -1;
        f->active = 1;
        f->d[0].wscale = f->d[1].wscale = -1;
        size_t k = bucket_of(ft, f);
        f->next = ft->buckets[k];
        ft->buckets[k] = idx;
        ft->nactive++;
        ev |= FEV_NEW_FLOW;
    }

    flow_t *f = &ft->v[idx];
    int dir = (f->cport == p->sport && ip_eq(&f->cli, &p->src)) ? 0 : 1;
    flow_dir_t *d = &f->d[dir];
    d->pkts++;
    d->bytes += p->wire_len;
    d->payload += p->payload_len;
    if (p->ts > f->last) f->last = p->ts;
    if (p->proto == IPP_TCP) ev |= tcp_update(f, dir, p);
    else d->last_ts = p->ts;

    *idx_out = idx;
    *dir_out = dir;
    return ev;
}

void flowtable_finish(flowtable_t *ft)
{
    for (size_t i = 0; i < ft->n; i++) {
        flow_t *f = &ft->v[i];
        if (f->active) finish_flow(f);
        f->next = -1;
    }
    for (size_t i = 0; i < ft->nbuckets; i++) ft->buckets[i] = -1;
    ft->nactive = 0;
}

const char *tcp_outcome_name(int o)
{
    static const char *const names[TO_COUNT] = {
        "nie dotyczy", "SYN bez odpowiedzi", "odrzucone (RST)", "półotwarte",
        "otwarte do końca zrzutu", "zamknięte poprawnie (FIN)", "zamknięte jednostronnie",
        "przerwane (RST)", "rozpoczęte przed zrzutem",
    };
    return (o >= 0 && o < TO_COUNT) ? names[o] : "?";
}

int tcp_outcome_failed(int o)
{
    return o == TO_UNANSWERED || o == TO_REJECTED || o == TO_HALF_OPEN;
}
