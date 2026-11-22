#ifndef PA_FIGURES_H
#define PA_FIGURES_H

#include <cairo.h>

#include "analysis.h"

enum {
    FIG_THROUGHPUT = 0, FIG_PACKET_RATE, FIG_PROTOCOLS, FIG_SIZES, FIG_TOP_HOSTS,
    FIG_TCP_PORTS, FIG_UDP_PORTS, FIG_TCP_FLAGS, FIG_TCP_STATES, FIG_RTT,
    FIG_FLOW_SIZE, FIG_FLOW_DUR, FIG_TCP_EVENTS, FIG_DNS, FIG_ANOMALIES, FIG_COUNT
};

#define FIG_W 720.0

const char *figure_file(int id);     /* nazwa pliku PNG */
const char *figure_title(int id);
int    figure_available(const analysis_t *A, int id);
double figure_height(const analysis_t *A, int id);
void   figure_draw(const analysis_t *A, int id, cairo_t *cr, double W, double H);

/* Zapisuje wszystkie dostępne wykresy jako PNG w katalogu dir.
 * Zwraca liczbę zapisanych plików (lub -1 przy błędzie). */
int figures_write_png(const analysis_t *A, const char *dir);

#endif
