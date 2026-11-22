/*
 * Nie korzystamy z netinet/..., bo układ struktur różni się między Linuksem
 * a BSD. Pola czytamy bajt po bajcie ze sprawdzaniem długości bufora.
 */
#ifndef PA_DECODE_H
#define PA_DECODE_H

#include "util.h"

/* Flagi TCP */
enum {
    TCPF_FIN = 0x01, TCPF_SYN = 0x02, TCPF_RST = 0x04, TCPF_PSH = 0x08,
    TCPF_ACK = 0x10, TCPF_URG = 0x20, TCPF_ECE = 0x40, TCPF_CWR = 0x80
};

/* Numery protokołów IANA używane w programie */
enum { IPP_ICMP = 1, IPP_TCP = 6, IPP_UDP = 17, IPP_ICMPV6 = 58 };

/* Wynik dekodowania */
enum {
    DEC_OK = 0,        /* pakiet IP zdekodowany (L4 opcjonalnie, patrz l4_ok) */
    DEC_NONIP,         /* poprawna ramka, ale nie IP (ARP, LLDP, ...) */
    DEC_TRUNC,         /* ramka zbyt krótka, by odczytać nagłówki L2/L3 */
    DEC_MALFORMED,     /* niespójne pola nagłówków */
    DEC_UNSUPPORTED    /* nieobsługiwany typ warstwy łącza */
};

typedef struct {
    double   ts;             /* sekundy od początku analizy */
    uint32_t wire_len;
    uint32_t cap_len;
    int      status;         /* DEC_* */
    uint16_t ethertype;
    int      vlan_tags;      /* liczba znaczników 802.1Q/802.1ad */

    int      ipv;            /* 4, 6 lub 0 */
    ipaddr_t src, dst;
    uint8_t  proto;          /* protokół L4 (numer IANA) */
    uint8_t  ttl;
    uint32_t ip_payload_len; /* długość danych za nagłówkami IP wg nagłówka */
    int      fragment;       /* datagram jest fragmentem */
    int      frag_nonfirst;  /* kolejny fragment (brak nagłówka L4) */

    int      l4_ok;          /* nagłówek L4 odczytany w całości */
    int      l4_trunc;       /* nagłówek L4 obcięty (snaplen) */
    int      l4_bad;         /* niespójny nagłówek L4 */
    uint16_t sport, dport;

    /* TCP */
    uint8_t  tcp_flags;
    uint32_t seq, ack;
    uint16_t win;
    uint16_t mss;            /* opcja MSS (0 = brak) */
    int8_t   wscale;         /* opcja Window Scale (-1 = brak) */
    uint8_t  sack_perm;

    /* Dane warstwy L4 */
    uint32_t payload_len;    /* deklarowana długość danych L4 */
    const uint8_t *payload;  /* przechwycone bajty danych (może ich być mniej) */
    uint32_t payload_caplen;

    /* ICMP / ICMPv6 */
    uint8_t  icmp_type, icmp_code;
    int      icmp_inner;     /* komunikat błędu zawiera nagłówek pakietu źródłowego */
    ipaddr_t in_src, in_dst;
    uint8_t  in_proto;
    uint16_t in_sport, in_dport;
} packet_t;

int decode_packet(int dlt, const uint8_t *data, uint32_t caplen, uint32_t wirelen,
                  double ts, packet_t *p);

/* Czy komunikat ICMP/ICMPv6 oznacza "port nieosiągalny" */
int icmp_is_port_unreach(const packet_t *p);
/* Czy komunikat ICMP/ICMPv6 oznacza "cel nieosiągalny" (dowolny kod) */
int icmp_is_unreach(const packet_t *p);

#endif
