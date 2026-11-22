/*
 * Każda funkcja rysuje cały wykres w prostokącie (0,0)-(W,H) bieżącego
 * kontekstu cairo, dzięki czemu ten sam kod generuje PNG i wykresy w PDF.
 */
#ifndef PA_CHART_H
#define PA_CHART_H

#include <cairo.h>
#include <stddef.h>

typedef struct { double r, g, b; } rgb_t;

extern const rgb_t C_SERIES[8];
extern const rgb_t C_SURFACE, C_PAGE, C_INK, C_INK2, C_MUTED, C_GRID, C_AXIS, C_WHITE;
extern const rgb_t C_SEV[3];      /* niski, średni, wysoki */
extern const rgb_t C_SEV_TEXT[3]; /* kolor tekstu na tle statusu */

enum { AL_LEFT = 0, AL_CENTER = 1, AL_RIGHT = 2 };

typedef enum { VF_NUM, VF_BYTES, VF_BITRATE, VF_PCT, VF_DUR } valfmt_t;

void        chart_set_font(const char *family);
const char *chart_get_font(void);

void   set_rgb(cairo_t *cr, rgb_t c);
void   set_rgba(cairo_t *cr, rgb_t c, double a);
void   txt_font(cairo_t *cr, double size, int bold);
double txt_width(cairo_t *cr, const char *s, double size, int bold);
void   txt_draw(cairo_t *cr, double x, double y, const char *s, double size, int bold,
                rgb_t col, int align);
/* Skraca tekst (z wielokropkiem), aby zmieścił się w maxw. */
void   txt_fit(cairo_t *cr, const char *s, double size, int bold, double maxw,
               char *out, size_t outlen);
void   round_rect(cairo_t *cr, double x, double y, double w, double h, double r);

/* Etykieta wartości (osie, podpisy słupków) */
const char *fmt_value(double v, valfmt_t f);

typedef struct {
    const char *title;
    const char *subtitle;
    const char *xlabel, *ylabel;
    int         nseries;
    const char *names[8];
    rgb_t       colors[8];
} chart_spec_t;

/* Szereg czasowy: x w sekundach od początku, y[s][i]; bands = pary (t0,t1)
 * zaznaczane w tle (np. wykryte skoki ruchu). */
void chart_lines(cairo_t *cr, double W, double H, const chart_spec_t *s,
                 const double *x, const double *const *y, int n, double xmax,
                 valfmt_t yf, const double *bands, int nbands);

/* Poziome słupki (ranking), wartości skumulowane z nseries serii: vals[s][i]. */
void chart_hbar(cairo_t *cr, double W, double H, const chart_spec_t *s,
                const char *const *labels, const double *const *vals, int n, valfmt_t vf);

/* Słupki pionowe (grupowane gdy nseries > 1): vals[s][i]. */
void chart_columns(cairo_t *cr, double W, double H, const chart_spec_t *s,
                   const char *const *labels, const double *const *vals, int n,
                   valfmt_t yf, int show_values);

/* Dystrybuanta empiryczna na osi logarytmicznej: sorted[s] - posortowane wartości. */
void chart_cdf(cairo_t *cr, double W, double H, const chart_spec_t *s,
               const double *const *sorted, const size_t *counts, valfmt_t xf, double xfloor);

/* Słupki segmentowe 100% (część całości): vals[row][seg], segmenty = serie spec. */
void chart_segbars(cairo_t *cr, double W, double H, const chart_spec_t *s,
                   const char *const *rows, const double *const *vals, int nrows);

typedef struct {
    char   label[112];
    double t0, t1;
    int    sev;
} gantt_item_t;

/* Oś czasu przedziałów (nieprawidłowości) kolorowanych wg ważności. */
void chart_gantt(cairo_t *cr, double W, double H, const chart_spec_t *s,
                 const gantt_item_t *items, int n, double tmax);

void chart_empty(cairo_t *cr, double W, double H, const chart_spec_t *s, const char *msg);

#endif
