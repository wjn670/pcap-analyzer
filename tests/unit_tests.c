#include <stdio.h>
#include <string.h>

#include "decode.h"
#include "dns.h"
#include "flow.h"
#include "util.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; printf("BŁĄD %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

/* Ethernet + IPv4 + TCP (SYN, MSS 1460, WS 7) */
static const uint8_t syn_pkt[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
    0x45, 0, 0, 52, 0, 0, 0x40, 0, 64, 6, 0, 0, 192, 168, 1, 10, 93, 184, 216, 34,
    0xc3, 0x50, 0x01, 0xbb, 0, 0, 0x10, 0, 0, 0, 0, 0, 0x80, 0x02, 0xfa, 0xf0, 0, 0, 0, 0,
    2, 4, 0x05, 0xb4, 1, 3, 3, 7, 1, 1, 4, 2};

static void test_decode(void)
{
    packet_t p;
    decode_packet(1, syn_pkt, sizeof syn_pkt, sizeof syn_pkt, 0, &p);
    CHECK(p.status == DEC_OK && p.ipv == 4 && p.proto == IPP_TCP && p.l4_ok);
    CHECK(p.sport == 50000 && p.dport == 443);
    CHECK(p.tcp_flags == TCPF_SYN && p.seq == 4096);
    CHECK(p.mss == 1460 && p.wscale == 7 && p.sack_perm);
    CHECK(strcmp(ip_str(&p.src), "192.168.1.10") == 0);

    /* ten sam pakiet ze znacznikiem VLAN */
    uint8_t v[sizeof syn_pkt + 4];
    memcpy(v, syn_pkt, 12);
    v[12] = 0x81; v[13] = 0; v[14] = 0; v[15] = 5;
    memcpy(v + 16, syn_pkt + 12, sizeof syn_pkt - 12);
    decode_packet(1, v, sizeof v, sizeof v, 0, &p);
    CHECK(p.status == DEC_OK && p.vlan_tags == 1 && p.dport == 443);

    /* obcięta ramka */
    decode_packet(1, syn_pkt, 20, 66, 0, &p);
    CHECK(p.status == DEC_TRUNC);
    /* IHL < 5 */
    uint8_t bad[sizeof syn_pkt];
    memcpy(bad, syn_pkt, sizeof bad);
    bad[14] = 0x43;
    decode_packet(1, bad, sizeof bad, sizeof bad, 0, &p);
    CHECK(p.status == DEC_MALFORMED);
    /* ARP */
    uint8_t arp[60] = {0};
    arp[12] = 0x08; arp[13] = 0x06;
    decode_packet(1, arp, 60, 60, 0, &p);
    CHECK(p.status == DEC_NONIP && p.ethertype == 0x0806);

    /* IPv6 + nagłówek hop-by-hop + UDP (surowe IP) */
    uint8_t v6[40 + 8 + 8 + 4] = {0x60};
    v6[4] = 0; v6[5] = 20; v6[6] = 0; v6[7] = 64;
    v6[8] = 0x20; v6[9] = 0x01; v6[10] = 0x0d; v6[11] = 0xb8; v6[23] = 1;
    v6[24] = 0x20; v6[25] = 0x01; v6[26] = 0x0d; v6[27] = 0xb8; v6[39] = 2;
    v6[40] = 17; v6[41] = 0;                       /* HbH: następny = UDP, długość 8 */
    v6[48] = 0x30; v6[49] = 0x39; v6[50] = 0; v6[51] = 53; v6[52] = 0; v6[53] = 12;
    decode_packet(101, v6, sizeof v6, sizeof v6, 0, &p);
    CHECK(p.status == DEC_OK && p.ipv == 6 && p.proto == IPP_UDP && p.l4_ok);
    CHECK(p.sport == 12345 && p.dport == 53 && p.payload_len == 4);
}

static packet_t mk(double ts, int fromcli, uint8_t fl, uint32_t seq, uint32_t ack, uint32_t len)
{
    packet_t p;
    memset(&p, 0, sizeof p);
    ip_parse("10.0.0.1", fromcli ? &p.src : &p.dst);
    ip_parse("10.0.0.2", fromcli ? &p.dst : &p.src);
    p.sport = fromcli ? 40000 : 80;
    p.dport = fromcli ? 80 : 40000;
    p.ipv = 4; p.proto = IPP_TCP; p.l4_ok = 1; p.status = DEC_OK;
    p.ts = ts; p.tcp_flags = fl; p.seq = seq; p.ack = ack; p.payload_len = len;
    p.win = 1000; p.wire_len = 54 + len; p.wscale = -1;
    return p;
}

static void test_flow(void)
{
    flowtable_t ft;
    flowtable_init(&ft);
    int32_t i; int d, ev;
    packet_t p;
    p = mk(0.000, 1, TCPF_SYN, 0xfffffff0u, 0, 0);            /* blisko zawinięcia numeracji */
    ev = flow_update(&ft, &p, 120, &i, &d);
    CHECK((ev & FEV_NEW_FLOW) && (ev & FEV_SYN) && d == 0);
    p = mk(0.010, 0, TCPF_SYN | TCPF_ACK, 500, 0xfffffff1u, 0); flow_update(&ft, &p, 120, &i, &d);
    CHECK(d == 1);
    p = mk(0.020, 1, TCPF_ACK, 0xfffffff1u, 501, 0); flow_update(&ft, &p, 120, &i, &d);
    CHECK(ft.v[i].established && ft.v[i].rtt > 0.0199 && ft.v[i].rtt < 0.0201);
    p = mk(0.030, 1, TCPF_ACK | TCPF_PSH, 0xfffffff1u, 501, 100); flow_update(&ft, &p, 120, &i, &d);
    p = mk(0.040, 1, TCPF_ACK | TCPF_PSH, 0x55u, 501, 100); flow_update(&ft, &p, 120, &i, &d);
    CHECK(ft.v[i].d[0].retrans == 0);                          /* zawinięcie, nie retransmisja */
    p = mk(0.500, 1, TCPF_ACK | TCPF_PSH, 0x55u, 501, 100);
    ev = flow_update(&ft, &p, 120, &i, &d);
    CHECK((ev & FEV_RETRANS) && ft.v[i].d[0].retrans == 1);
    p = mk(0.600, 1, TCPF_FIN | TCPF_ACK, 0xb9u, 501, 0); flow_update(&ft, &p, 120, &i, &d);
    p = mk(0.610, 0, TCPF_FIN | TCPF_ACK, 501, 0xbau, 0); flow_update(&ft, &p, 120, &i, &d);
    flowtable_finish(&ft);
    CHECK(ft.n == 1 && ft.v[0].outcome == TO_CLOSED);
    flowtable_free(&ft);

    /* SYN odrzucony przez RST */
    flowtable_init(&ft);
    p = mk(0, 1, TCPF_SYN, 1, 0, 0); flow_update(&ft, &p, 120, &i, &d);
    p = mk(0.001, 0, TCPF_RST | TCPF_ACK, 0, 2, 0); flow_update(&ft, &p, 120, &i, &d);
    flowtable_finish(&ft);
    CHECK(ft.v[0].outcome == TO_REJECTED && tcp_outcome_failed(ft.v[0].outcome));
    flowtable_free(&ft);
}

static void test_dns(void)
{
    const uint8_t q[] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
                         3, 'W', 'w', 'W', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
    dns_msg_t m;
    CHECK(dns_parse(q, sizeof q, &m) == 0);
    CHECK(strcmp(m.qname, "www.example.com") == 0 && m.qtype == 1 && !m.qr);
    CHECK(!dns_is_suspicious(&m));
    CHECK(dns_parse(q, 20, &m) != 0);                         /* obcięta nazwa */
}

static void test_format(void)
{
    CHECK(strcmp(fmt_num(1234567.891, 2), "1\xC2\xA0" "234\xC2\xA0" "567,89") == 0);
    CHECK(strcmp(fmt_num(1234, 0), "1234") == 0);
    CHECK(strcmp(fmt_bytes(1500000), "1,50\xC2\xA0MB") == 0);
    CHECK(strcmp(fmt_pct(0.1234, 1), "12,3%") == 0);
    CHECK(strcmp(fmt_port(6, 443), "443 (https)") == 0);
    double v[] = {5, 1, 4, 2, 3};
    CHECK(median_inplace(v, 5) == 3);
    ipaddr_t a;
    ip_parse("10.1.2.3", &a);
    CHECK(ip_is_private(&a));
    ip_parse("8.8.8.8", &a);
    CHECK(!ip_is_private(&a));
}

int main(void)
{
    test_decode();
    test_flow();
    test_dns();
    test_format();
    printf("Testy jednostkowe: %d/%d zaliczonych\n", checks - failures, checks);
    return failures ? 1 : 0;
}
