#!/bin/sh
# Testy całościowe: generuje syntetyczne pliki pcap, uruchamia analizator
# i sprawdza wyniki. Użycie: sh tests/e2e.sh ./pcap-analyzer ./build/pcapgen
set -u
BIN=${1:-./pcap-analyzer}
GEN=${2:-./build/pcapgen}
OUT=tests/out
FAIL=0
mkdir -p "$OUT"

check() {  # opis, polecenie
    if sh -c "$2" >/dev/null 2>&1; then echo "  OK    $1"; else echo "  BŁĄD  $1"; FAIL=1; fi
}

"$GEN" mixed "$OUT/mixed.pcap" 2>/dev/null
"$GEN" normal "$OUT/normal.pcap" 2>/dev/null

echo "== ruch z atakami (mixed.pcap)"
"$BIN" -q -o "$OUT/mixed" "$OUT/mixed.pcap" || FAIL=1
A="$OUT/mixed/anomalie.csv"
S="$OUT/mixed/podsumowanie.txt"
check "raport PDF"                 "head -c 5 $OUT/mixed/raport.pdf | grep -q '%PDF-'"
check "15 wykresów PNG"            "[ \$(ls $OUT/mixed/wykresy/*.png | wc -l) -eq 15 ]"
check "liczba pakietów"            "grep -qx 'packets=14277' $S"
check "skanowanie portów TCP"      "grep -q '^wysoki,PORT_SCAN' $A"
check "skanowanie portów UDP"      "grep -q ',UDP_SCAN,' $A"
check "SYN flood"                  "grep -q '^wysoki,SYN_FLOOD' $A"
check "zalew UDP"                  "grep -q ',UDP_FLOOD,' $A"
check "skok natężenia ruchu"       "grep -q ',TRAFFIC_SPIKE,' $A"
check "nieprawidłowe flagi TCP"    "grep -q ',BAD_TCP_FLAGS,' $A"
check "tunelowanie DNS"            "grep -q ',DNS_TUNNEL,' $A"
check "NXDOMAIN"                   "grep -q ',DNS_NXDOMAIN,' $A"
check "retransmisje TCP"           "grep -q ',TCP_RETRANS,' $A"
check "zerowe okno"                "grep -q ',ZERO_WINDOW,' $A"
check "protokoły nieszyfrowane"    "grep -q ',CLEARTEXT,' $A"
check "uszkodzone pakiety"         "grep -q ',MALFORMED,' $A"
check "ramki VLAN rozpoznane"      "grep -q '^vlan=[1-9]' $S"

echo "== ruch typowy (normal.pcap) - brak fałszywych alarmów"
"$BIN" -q -o "$OUT/normal" "$OUT/normal.pcap" || FAIL=1
S2="$OUT/normal/podsumowanie.txt"
check "0 nieprawidłowości wysokich" "grep -qx 'anomalies_high=0' $S2"
check "0 nieprawidłowości średnich" "grep -qx 'anomalies_medium=0' $S2"
check "połączenia zamknięte FIN"    "grep -q '^tcp_state_closed=[1-9]' $S2"

echo "== kilka plików naraz (scalanie)"
"$BIN" -q --no-pdf --no-png -o "$OUT/multi" "$OUT/normal.pcap" "$OUT/mixed.pcap" || FAIL=1
check "suma pakietów z dwóch plików" "grep -qx 'packets=16596' $OUT/multi/podsumowanie.txt"

echo "== błędne wejście"
check "nieistniejący plik -> kod błędu" "! $BIN -q -o $OUT/x /nonexistent.pcap"

[ $FAIL -eq 0 ] && echo "Wszystkie testy całościowe zaliczone." || echo "Niektóre testy nie przeszły."
exit $FAIL
