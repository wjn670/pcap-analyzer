/*
 * Prosty skład PDF na cairo. Dokument jest składany dwa razy: pierwszy
 * przebieg (bez zapisu) liczy strony i numery stron sekcji do spisu treści,
 * drugi rysuje właściwy dokument.
 */
#ifndef PA_PDFDOC_H
#define PA_PDFDOC_H

#include <cairo.h>

#include "analysis.h"
#include "chart.h"

#define DOC_MAX_TOC 64

typedef struct {
    int    level;
    char   title[128];
    int    page;
} toc_entry_t;

typedef struct {
    cairo_surface_t *surf;
    cairo_t *cr;
    int     dry;
    double  W, H;
    double  ml, mr, mt, mb;
    double  y;
    int     page;
    int     total_pages;                /* z przebiegu próbnego, 0 = nieznana */
    char    head_left[160], head_right[200], foot_left[200];
    toc_entry_t toc[DOC_MAX_TOC];
    int     ntoc;
    const toc_entry_t *toc_ref;         /* wpisy z przebiegu próbnego */
    int     ntoc_ref;
    int     fig_no, tab_no;
    int     outline_h1;
} doc_t;

typedef struct {
    int     ncols;
    const char *head[12];
    double  w[12];                      /* udział w szerokości */
    int     align[12];
    char  **cells;                      /* nrows * ncols */
    int    *sev;                        /* ważność wiersza (-1 = brak) */
    int     badge_col;                  /* kolumna rysowana jako plakietka ważności (-1) */
    int     nrows, cap;
    double  font;
} table_t;

int  doc_begin(doc_t *d, const char *path, const char *title, const char *author);
int  doc_end(doc_t *d);                 /* zwraca liczbę stron */
void doc_new_page(doc_t *d, int decorations);
void doc_ensure(doc_t *d, double h);
double doc_width(const doc_t *d);

void doc_h1(doc_t *d, const char *text);
void doc_h2(doc_t *d, const char *text);
void doc_par(doc_t *d, const char *text, double size, rgb_t col);
void doc_text(doc_t *d, const char *text);           /* akapit podstawowy */
void doc_note(doc_t *d, const char *text);           /* drobny, wyszarzony */
void doc_bullet(doc_t *d, const char *text);
void doc_space(doc_t *d, double h);
void doc_kv(doc_t *d, const char *const *keys, const char *const *vals, int n);
void doc_table(doc_t *d, const table_t *t, const char *caption);
void doc_figure(doc_t *d, const analysis_t *A, int fig_id);
void doc_toc(doc_t *d);
double doc_badge(cairo_t *cr, double x, double y, int sev, double size);

/* Łamanie tekstu na wiersze o szerokości maxw; zwraca wysokość. */
double doc_wrap(doc_t *d, double x, double y, double maxw, const char *text, double size,
                int bold, rgb_t col, double lh, int draw);

void table_init(table_t *t, int ncols);
void table_col(table_t *t, int i, const char *head, double w, int align);
void table_add(table_t *t, ...);        /* dokładnie ncols napisów */
void table_set_sev(table_t *t, int sev);/* ważność ostatnio dodanego wiersza */
void table_free(table_t *t);

#endif
