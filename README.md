# pcap-analyzer

[![CI](https://github.com/wjn670/pcap-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/wjn670/pcap-analyzer/actions/workflows/ci.yml)

Narzędzie w języku C dla systemu Linux, które analizuje komunikację **TCP i UDP** zapisaną w plikach
`.pcap` / `.pcapng` i generuje:

- **raport PDF** (strona tytułowa z kluczowymi liczbami i wnioskami, spis treści, 8 sekcji analizy, metodyka),
- **15 wykresów PNG** (ruch w czasie, protokoły, hosty, usługi, stany TCP, RTT, rozkłady przepływów, DNS, oś czasu nieprawidłowości),
- pliki **CSV** z przepływami i nieprawidłowościami oraz `podsumowanie.txt` (klucz=wartość).

## Zależności

Tylko standardowa biblioteka C i dwie lekkie, powszechnie dostępne biblioteki:

| Biblioteka | Do czego |
|---|---|
| `libpcap` | odczyt plików pcap i pcapng |
| `cairo` | rysowanie wykresów (PNG) i skład raportu (PDF) - ten sam kod rysuje oba formaty |

```bash
# Debian / Ubuntu
sudo apt install build-essential pkg-config libpcap-dev libcairo2-dev fonts-dejavu-core
# Fedora
sudo dnf install gcc make pkgconf libpcap-devel cairo-devel dejavu-sans-fonts
```

## Kompilacja i uruchomienie

```bash
make                 # program ./pcap-analyzer
make test            # testy jednostkowe + testy całościowe na wygenerowanych pcapach
make sanitize        # testy z AddressSanitizer i UBSan
```

```bash
./pcap-analyzer -o wynik zrzut.pcap
./pcap-analyzer -o wynik -t "Sieć biurowa - 22.11" eth0.pcap wlan0.pcapng   # kilka plików naraz
./pcap-analyzer --help
```

Wyniki w katalogu `wynik/`:

```
raport.pdf
wykresy/01_przeplywnosc.png ... 15_nieprawidlowosci.png
przeplywy.csv  anomalie.csv  podsumowanie.txt
```

Najważniejsze opcje: `-n` długość rankingów, `-b` szerokość przedziału czasu, `--flow-timeout`,
progi detekcji (`--scan-ports`, `--syn-flood`, `--udp-flood`, `--spike-k`, `--retrans`, ...),
`--no-pdf/--no-png/--no-csv`. Zmienna `SOURCE_DATE_EPOCH` ustala datę w raporcie (powtarzalne wyniki).

## Architektura

```
pliki pcap ──► reader ──► decode ──► analysis ──┬─► flow (przepływy, stan TCP)
 (libpcap,     (scalanie   (L2→L3→L4,           ├─► dns (zapytania, nazwy)
  2 przebiegi)  k-drogowe)  kontrola granic)    └─► statystyki, szeregi czasowe, hosty, porty
                                                        │
                                                   anomaly (detektory)
                                                        │
                        ┌───────────────┬───────────────┼───────────────┐
                     figures ──► chart (cairo)       report ──► pdfdoc   export (CSV/TXT)
                        │                              │
                     PNG (2x)                      PDF (wykresy wektorowe)
```

| Moduł | Odpowiedzialność |
|---|---|
| `reader.c` | przebieg 1: metadane plików (typ łącza, zakres czasu); przebieg 2: pakiety ze wszystkich plików scalone chronologicznie |
| `decode.c` | Ethernet (VLAN, PPPoE, MPLS), Linux SLL/SLL2, raw IP, loopback; IPv4/IPv6 z nagłówkami rozszerzeń; TCP (z opcjami), UDP, ICMP/ICMPv6 z cytowanym nagłówkiem. Bez struktur z `netinet/*` - przenośne między Linuksem a BSD |
| `flow.c` | tablica haszująca przepływów dwukierunkowych, wykrywanie klienta, stan połączenia TCP, RTT uzgadniania, retransmisje, poza kolejnością, luki, dup ACK, zerowe okno |
| `dns.c` | parser nagłówka i pytania DNS, typy zapytań, kody odpowiedzi, entropia etykiet |
| `analysis.c` | potok pakietów, statystyki globalne, szeregi czasowe, hosty, porty, rankingi |
| `anomaly.c` | detektory nieprawidłowości (poniżej) |
| `chart.c` | biblioteka wykresów: liniowy, słupki poziome/pionowe, dystrybuanta (oś log.), słupek segmentowy, oś czasu |
| `figures.c` | 15 wykresów raportu zbudowanych z wyników analizy |
| `pdfdoc.c` | skład PDF: nagłówki/stopki „Strona X z Y”, zakładki PDF, spis treści z odnośnikami, tabele z powtarzanym nagłówkiem; dwa przebiegi składu |
| `report.c` | treść raportu |
| `export.c` | CSV i podsumowanie |

## Metody analizy

- **Ruch w czasie** - automatyczny dobór szerokości przedziału (~240 punktów), przepływność i natężenie z podziałem na TCP/UDP/inne.
- **Przepływy** - 5-krotka, zakończenie po FIN/RST i ponownym użyciu portów albo po limicie bezczynności.
- **TCP** - stan końcowy (nawiązane, zamknięte FIN, przerwane RST, odrzucone, bez odpowiedzi, półotwarte, rozpoczęte przed zrzutem), RTT od SYN do ACK klienta, arytmetyka numerów sekwencyjnych odporna na zawinięcie 2^32.
- **Rozkłady** - histogram rozmiarów ramek, histogram RTT w przedziałach logarytmicznych, dystrybuanty wielkości i czasu trwania przepływów.

### Wykrywane nieprawidłowości

| Detektor | Kryterium (domyślne progi) |
|---|---|
| Skanowanie portów TCP / UDP | ≥ 15 portów jednego hosta, ≥ 50% zamkniętych/bez odpowiedzi; lista otwartych portów |
| Przeszukiwanie hostów | ≥ 10 hostów na jednym porcie |
| SYN flood | ≥ 200 nieudanych SYN do usługi; rozpoznanie fałszowanych źródeł |
| Zalew UDP | ≥ 1000 pak./s do hosta, < 10% odpowiedzi |
| Skok natężenia ruchu | odporny z-score: mediana + 6·MAD (z dolną granicą szumu Poissona) |
| Nieprawidłowe flagi TCP | NULL, FIN, XMAS, SYN+FIN, SYN+RST (skany stealth) |
| Retransmisje | ≥ 2% segmentów z danymi; najgorsze połączenia |
| Tunelowanie DNS / DGA | etykiety ≥ 30 znaków o entropii ≥ 3,5 bit/znak; nadmiar NXDOMAIN |
| Inne | zerowe okno TCP, nadmiar RST, LAND, ICMP „nieosiągalny”, uszkodzone nagłówki, protokoły nieszyfrowane |

## Testy

`tools/pcapgen.c` generuje syntetyczne pliki pcap z ruchem typowym oraz ze scenariuszami ataków.
`tests/e2e.sh` sprawdza, czy każdy scenariusz jest wykrywany, a w ruchu typowym nie ma fałszywych
alarmów. `tests/unit_tests.c` testuje dekoder (VLAN, IPv6, uszkodzone ramki), śledzenie TCP
(zawinięcie numerów, retransmisje, stany), parser DNS i formatowanie.

## Ograniczenia

Analiza dotyczy wyłącznie nagłówków (bez inspekcji treści szyfrowanej), fragmenty IP nie są składane,
wykrywanie retransmisji nie uwzględnia SACK, a detekcja nieprawidłowości jest heurystyczna.

## Autorzy

| Osoba | Zakres |
|---|---|
| Wiktor Nowakowski | odczyt i dekodowanie pakietów (`reader`, `decode`) |
| Marcel Szulc | przepływy, TCP, DNS (`flow`, `dns`, `analysis`) |
| Robert Krajniak | wykrywanie nieprawidłowości, testy (`anomaly`, `tests/`, `tools/`) |
| Kacper Krzywicki | wykresy i raport PDF (`chart`, `figures`, `pdfdoc`, `report`, `export`) |
