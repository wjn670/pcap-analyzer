/*
 * Obsługiwane typy łącza: Ethernet (802.1Q/802.1ad, PPPoE, MPLS, LLC/SNAP),
 * Linux SLL/SLL2 (tcpdump -i any), raw IPv4/IPv6, NULL/LOOP (loopback BSD/macOS).
 */
#include "decode.h"

#include <string.h>

#define DLT_NULL_       0
#define DLT_EN10MB_     1
#define DLT_RAW_A       12   /* DLT_RAW na większości systemów */
#define DLT_RAW_B       14   /* DLT_RAW na OpenBSD */
#define LINKTYPE_RAW_   101
#define DLT_LOOP_       108
#define DLT_LINUX_SLL_  113
#define LINKTYPE_IPV4_  228
#define LINKTYPE_IPV6_  229
#define DLT_LINUX_SLL2_ 276

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static int decode_ip(const uint8_t *d, uint32_t len, packet_t *p);
static int decode_ipv4(const uint8_t *d, uint32_t len, packet_t *p);
static int decode_ipv6(const uint8_t *d, uint32_t len, packet_t *p);

/* ---- Warstwa 4 ---- */

/* Nagłówek pakietu zacytowany w komunikacie ICMP o błędzie. */
static void decode_icmp_inner(const uint8_t *d, uint32_t len, packet_t *p)
{
    if (len < 1) return;
    int v = d[0] >> 4;
    uint32_t off;
    if (v == 4) {
        if (len < 20) return;
        off = (uint32_t)(d[0] & 0x0f) * 4;
        if (off < 20) return;
        p->in_src.v = p->in_dst.v = 4;
        memcpy(p->in_src.a, d + 12, 4);
        memcpy(p->in_dst.a, d + 16, 4);
        p->in_proto = d[9];
    } else if (v == 6) {
        if (len < 40) return;
        off = 40;
        p->in_src.v = p->in_dst.v = 6;
        memcpy(p->in_src.a, d + 8, 16);
        memcpy(p->in_dst.a, d + 24, 16);
        p->in_proto = d[6];
    } else {
        return;
    }
    p->icmp_inner = 1;
    if ((p->in_proto == IPP_TCP || p->in_proto == IPP_UDP) && len >= off + 4) {
        p->in_sport = rd16(d + off);
        p->in_dport = rd16(d + off + 2);
    }
}

/*
 * d       - początek nagłówka L4
 * caplen  - liczba przechwyconych bajtów od d (ograniczona do długości datagramu)
 * decl    - deklarowana w nagłówku IP długość danych L4
 */
static void decode_l4(const uint8_t *d, uint32_t caplen, uint32_t decl, packet_t *p)
{
    switch (p->proto) {
    case IPP_TCP: {
        if (caplen < 20) { p->l4_trunc = 1; return; }
        uint32_t doff = (uint32_t)(d[12] >> 4) * 4;
        if (doff < 20 || doff > decl) { p->l4_bad = 1; return; }
        p->sport = rd16(d);
        p->dport = rd16(d + 2);
        p->seq = rd32(d + 4);
        p->ack = rd32(d + 8);
        p->tcp_flags = d[13];
        p->win = rd16(d + 14);
        if (caplen >= doff) {
            /* opcje TCP */
            uint32_t i = 20;
            while (i < doff) {
                uint8_t kind = d[i];
                if (kind == 0) break;
                if (kind == 1) { i++; continue; }
                if (i + 1 >= doff) break;
                uint8_t olen = d[i + 1];
                if (olen < 2 || i + olen > doff) break;
                if (kind == 2 && olen == 4) p->mss = rd16(d + i + 2);
                else if (kind == 3 && olen == 3) p->wscale = (int8_t)(d[i + 2] > 14 ? 14 : d[i + 2]);
                else if (kind == 4 && olen == 2) p->sack_perm = 1;
                i += olen;
            }
        }
        p->payload_len = decl - doff;
        if (caplen > doff) {
            p->payload = d + doff;
            p->payload_caplen = PA_MIN(caplen - doff, p->payload_len);
        }
        p->l4_ok = 1;
        break;
    }
    case IPP_UDP: {
        if (caplen < 8) { p->l4_trunc = 1; return; }
        p->sport = rd16(d);
        p->dport = rd16(d + 2);
        uint32_t ulen = rd16(d + 4);
        if (ulen == 0) {
            ulen = decl;                         /* jumbogram IPv6 / offload */
        } else if (ulen < 8) {
            p->l4_bad = 1;
            return;
        } else if (ulen > decl) {
            if (!p->fragment) p->l4_bad = 1;     /* pierwszy fragment: normalne */
            ulen = decl;
        }
        p->payload_len = ulen - 8;
        if (caplen > 8) {
            p->payload = d + 8;
            p->payload_caplen = PA_MIN(caplen - 8, p->payload_len);
        }
        p->l4_ok = 1;
        break;
    }
    case IPP_ICMP:
    case IPP_ICMPV6: {
        if (caplen < 4) { p->l4_trunc = 1; return; }
        p->icmp_type = d[0];
        p->icmp_code = d[1];
        p->l4_ok = 1;
        p->payload_len = decl >= 8 ? decl - 8 : 0;
        int err;
        if (p->proto == IPP_ICMP)  /* unreachable, source quench, redirect, time exceeded, param problem */
            err = d[0] == 3 || d[0] == 4 || d[0] == 5 || d[0] == 11 || d[0] == 12;
        else                       /* unreachable, packet too big, time exceeded, param problem */
            err = d[0] >= 1 && d[0] <= 4;
        if (err && caplen > 8) decode_icmp_inner(d + 8, caplen - 8, p);
        break;
    }
    default:
        break;
    }
}

/* ---- Warstwa 3 ---- */

static int decode_ipv4(const uint8_t *d, uint32_t len, packet_t *p)
{
    if (len < 20) return p->status = DEC_TRUNC;
    if ((d[0] >> 4) != 4) return p->status = DEC_MALFORMED;
    uint32_t ihl = (uint32_t)(d[0] & 0x0f) * 4;
    if (ihl < 20) return p->status = DEC_MALFORMED;
    if (len < ihl) return p->status = DEC_TRUNC;

    p->ipv = 4;
    p->src.v = p->dst.v = 4;
    memcpy(p->src.a, d + 12, 4);
    memcpy(p->dst.a, d + 16, 4);
    p->ttl = d[8];
    p->proto = d[9];

    uint32_t tot = rd16(d + 2);
    if (tot == 0) tot = len;                  /* TSO: długość nieznana */
    if (tot < ihl) return p->status = DEC_MALFORMED;

    uint16_t frag = rd16(d + 6);
    uint32_t foff = (uint32_t)(frag & 0x1fff) * 8;
    p->fragment = (frag & 0x2000) || foff;
    p->frag_nonfirst = foff > 0;
    p->ip_payload_len = tot - ihl;

    p->status = DEC_OK;
    if (p->frag_nonfirst) return DEC_OK;
    uint32_t avail = PA_MIN(len, tot) - ihl;  /* ramka może zawierać wypełnienie */
    decode_l4(d + ihl, avail, tot - ihl, p);
    return DEC_OK;
}

static int decode_ipv6(const uint8_t *d, uint32_t len, packet_t *p)
{
    if (len < 40) return p->status = DEC_TRUNC;
    if ((d[0] >> 4) != 6) return p->status = DEC_MALFORMED;

    p->ipv = 6;
    p->src.v = p->dst.v = 6;
    memcpy(p->src.a, d + 8, 16);
    memcpy(p->dst.a, d + 24, 16);
    p->ttl = d[7];

    uint32_t plen = rd16(d + 4);
    if (plen == 0) plen = len - 40;           /* jumbogram lub offload */
    uint32_t end = 40 + plen;
    uint32_t avail_end = PA_MIN(len, end);
    uint8_t nh = d[6];
    uint32_t off = 40;

    p->status = DEC_OK;
    for (int guard = 0; guard < 12; guard++) {
        if (nh == 0 || nh == 43 || nh == 60 || nh == 135 || nh == 139 || nh == 140) {
            if (avail_end < off + 8) { p->proto = nh; p->l4_trunc = 1; return DEC_OK; }
            uint32_t elen = ((uint32_t)d[off + 1] + 1) * 8;
            nh = d[off];
            off += elen;
        } else if (nh == 44) {                /* nagłówek fragmentacji */
            if (avail_end < off + 8) { p->proto = nh; p->l4_trunc = 1; return DEC_OK; }
            uint16_t fo = rd16(d + off + 2);
            p->fragment = 1;
            p->frag_nonfirst = (fo & 0xfff8) != 0;
            nh = d[off];
            off += 8;
            if (p->frag_nonfirst) {
                p->proto = nh;
                p->ip_payload_len = end > off ? end - off : 0;
                return DEC_OK;
            }
        } else if (nh == 51) {                /* AH */
            if (avail_end < off + 8) { p->proto = nh; p->l4_trunc = 1; return DEC_OK; }
            uint32_t elen = ((uint32_t)d[off + 1] + 2) * 4;
            nh = d[off];
            off += elen;
        } else {
            break;
        }
        if (off > end) return p->status = DEC_MALFORMED;
    }
    p->proto = nh;
    p->ip_payload_len = end - off;
    decode_l4(d + off, avail_end > off ? avail_end - off : 0, end - off, p);
    return DEC_OK;
}

static int decode_ip(const uint8_t *d, uint32_t len, packet_t *p)
{
    if (len < 1) return p->status = DEC_TRUNC;
    switch (d[0] >> 4) {
    case 4: p->ethertype = 0x0800; return decode_ipv4(d, len, p);
    case 6: p->ethertype = 0x86DD; return decode_ipv6(d, len, p);
    default: return p->status = DEC_MALFORMED;
    }
}

/* ---- Warstwa 2 ---- */

static int decode_ethertype(uint16_t et, const uint8_t *d, uint32_t len, packet_t *p)
{
    p->ethertype = et;
    switch (et) {
    case 0x0800: return decode_ipv4(d, len, p);
    case 0x86DD: return decode_ipv6(d, len, p);
    case 0x8864: {                            /* PPPoE - sesja */
        if (len < 8) return p->status = DEC_TRUNC;
        uint16_t pp = rd16(d + 6);
        if (pp == 0x0021) return decode_ipv4(d + 8, len - 8, p);
        if (pp == 0x0057) return decode_ipv6(d + 8, len - 8, p);
        return p->status = DEC_NONIP;
    }
    case 0x8847:
    case 0x8848: {                            /* MPLS: pomiń stos etykiet */
        uint32_t off = 0;
        for (int i = 0; i < 8; i++) {
            if (len < off + 4) return p->status = DEC_TRUNC;
            int bos = d[off + 2] & 1;
            off += 4;
            if (bos) return decode_ip(d + off, len - off, p);
        }
        return p->status = DEC_MALFORMED;
    }
    default:
        return p->status = DEC_NONIP;
    }
}

int decode_packet(int dlt, const uint8_t *d, uint32_t caplen, uint32_t wirelen,
                  double ts, packet_t *p)
{
    memset(p, 0, sizeof *p);
    p->ts = ts;
    p->wire_len = wirelen;
    p->cap_len = caplen;
    p->wscale = -1;

    switch (dlt) {
    case DLT_EN10MB_: {
        if (caplen < 14) return p->status = DEC_TRUNC;
        uint32_t off = 14;
        uint16_t et = rd16(d + 12);
        while (et == 0x8100 || et == 0x88a8 || et == 0x9100) {
            if (p->vlan_tags >= 4 || caplen < off + 4) return p->status = DEC_TRUNC;
            et = rd16(d + off + 2);
            off += 4;
            p->vlan_tags++;
        }
        if (et < 0x0600) {                    /* 802.3 + LLC; IP tylko przez SNAP */
            if (caplen >= off + 8 && d[off] == 0xAA && d[off + 1] == 0xAA && d[off + 2] == 0x03) {
                et = rd16(d + off + 6);
                off += 8;
            } else {
                p->ethertype = 0;
                return p->status = DEC_NONIP;
            }
        }
        return decode_ethertype(et, d + off, caplen - off, p);
    }
    case DLT_LINUX_SLL_:
        if (caplen < 16) return p->status = DEC_TRUNC;
        return decode_ethertype(rd16(d + 14), d + 16, caplen - 16, p);
    case DLT_LINUX_SLL2_:
        if (caplen < 20) return p->status = DEC_TRUNC;
        return decode_ethertype(rd16(d), d + 20, caplen - 20, p);
    case DLT_NULL_:
    case DLT_LOOP_: {
        if (caplen < 4) return p->status = DEC_TRUNC;
        /* Rodzina adresów: DLT_LOOP - porządek sieciowy, DLT_NULL - porządek
         * hosta, który zapisał plik (nieznany), więc sprawdzamy oba. */
        uint32_t be = rd32(d);
        uint32_t le = (uint32_t)d[0] | ((uint32_t)d[1] << 8) | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
        uint32_t fam = (dlt == DLT_LOOP_ || be < 256) ? be : le;
        if (fam == 2 || fam == 10 || fam == 24 || fam == 28 || fam == 30)
            return decode_ip(d + 4, caplen - 4, p);
        return p->status = DEC_NONIP;
    }
    case DLT_RAW_A:
    case DLT_RAW_B:
    case LINKTYPE_RAW_:
    case LINKTYPE_IPV4_:
    case LINKTYPE_IPV6_:
        return decode_ip(d, caplen, p);
    default:
        return p->status = DEC_UNSUPPORTED;
    }
}

int icmp_is_unreach(const packet_t *p)
{
    if (!p->l4_ok) return 0;
    return (p->proto == IPP_ICMP && p->icmp_type == 3) ||
           (p->proto == IPP_ICMPV6 && p->icmp_type == 1);
}

int icmp_is_port_unreach(const packet_t *p)
{
    if (!p->l4_ok) return 0;
    return (p->proto == IPP_ICMP && p->icmp_type == 3 && p->icmp_code == 3) ||
           (p->proto == IPP_ICMPV6 && p->icmp_type == 1 && p->icmp_code == 4);
}
