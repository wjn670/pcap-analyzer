#include "pdfdoc.h"
#include "figures.h"

#include <cairo-pdf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HAVE_PDF_TAGS (CAIRO_VERSION >= CAIRO_VERSION_ENCODE(1, 16, 0))

static const rgb_t C_ZEBRA = {0xf4 / 255.0, 0xf4 / 255.0, 0xf1 / 255.0};

/* ---- Strony ---- */

static int g_fresh;   /* bieżąca strona nie ma jeszcze treści */

double doc_width(const doc_t *d) { return d->W - d->ml - d->mr; }

static void decorations(doc_t *d)
{
    cairo_t *cr = d->cr;
    double y = d->mt - 26;
    char buf[256];
    txt_draw(cr, d->ml, y, d->head_left, 7.5, 0, C_MUTED, AL_LEFT);
    txt_fit(cr, d->head_right, 7.5, 0, doc_width(d) * 0.5, buf, sizeof buf);
    txt_draw(cr, d->W - d->mr, y, buf, 7.5, 0, C_MUTED, AL_RIGHT);
    set_rgb(cr, C_GRID);
    cairo_set_line_width(cr, 0.6);
    cairo_move_to(cr, d->ml, y + 7);
    cairo_line_to(cr, d->W - d->mr, y + 7);
    cairo_stroke(cr);

    double fy = d->H - d->mb + 30;
    txt_draw(cr, d->ml, fy, d->foot_left, 7.5, 0, C_MUTED, AL_LEFT);
    if (d->total_pages > 0) snprintf(buf, sizeof buf, "Strona %d z %d", d->page, d->total_pages);
    else snprintf(buf, sizeof buf, "Strona %d", d->page);
    txt_draw(cr, d->W - d->mr, fy, buf, 7.5, 0, C_MUTED, AL_RIGHT);
}

void doc_new_page(doc_t *d, int deco)
{
    if (d->page > 0) cairo_show_page(d->cr);
    d->page++;
    d->y = d->mt;
    g_fresh = 1;
    if (deco) decorations(d);
}

void doc_ensure(doc_t *d, double h)
{
    if (d->page == 0 || d->y + h > d->H - d->mb) doc_new_page(d, 1);
    g_fresh = 0;
}

void doc_space(doc_t *d, double h)
{
    d->y += h;
}

int doc_begin(doc_t *d, const char *path, const char *title, const char *author)
{
    d->W = 595.28;   /* A4 w punktach */
    d->H = 841.89;
    d->ml = d->mr = 54;
    d->mt = 70;
    d->mb = 62;
    d->dry = path == NULL;
    d->page = 0;
    d->ntoc = 0;
    d->fig_no = d->tab_no = 0;
    d->outline_h1 = 0;
    if (d->dry) d->surf = cairo_pdf_surface_create_for_stream(NULL, NULL, d->W, d->H);
    else d->surf = cairo_pdf_surface_create(path, d->W, d->H);
    if (cairo_surface_status(d->surf) != CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(d->surf);
        d->surf = NULL;
        return -1;
    }
#if HAVE_PDF_TAGS
    if (!d->dry) {
        cairo_pdf_surface_set_metadata(d->surf, CAIRO_PDF_METADATA_TITLE, title);
        cairo_pdf_surface_set_metadata(d->surf, CAIRO_PDF_METADATA_AUTHOR, author);
        cairo_pdf_surface_set_metadata(d->surf, CAIRO_PDF_METADATA_CREATOR, PA_NAME " " PA_VERSION);
        cairo_pdf_surface_set_metadata(d->surf, CAIRO_PDF_METADATA_SUBJECT,
                                       "Analiza komunikacji TCP i UDP z plików pcap");
    }
#else
    (void)title;
    (void)author;
#endif
    d->cr = cairo_create(d->surf);
    return 0;
}

int doc_end(doc_t *d)
{
    int pages = d->page;
    cairo_destroy(d->cr);
    cairo_surface_finish(d->surf);
    cairo_status_t st = cairo_surface_status(d->surf);
    cairo_surface_destroy(d->surf);
    d->cr = NULL;
    d->surf = NULL;
    return st == CAIRO_STATUS_SUCCESS ? pages : -1;
}

/* ---- Tekst ---- */

/* Wyznacza kolejny wiersz tekstu mieszczący się w maxw (łamanie na spacjach,
 * twarde łamanie bardzo długich słów, '\n' wymusza nowy wiersz). */
static int next_line(cairo_t *cr, const char **pp, double maxw, double size, int bold,
                     char *out, size_t outn)
{
    const char *p = *pp;
    while (*p == ' ') p++;
    if (!*p) return 0;
    if (*p == '\n') {
        out[0] = '\0';
        *pp = p + 1;
        return 1;
    }
    char buf[2048];
    size_t best = 0, i = 0;
    for (;;) {
        size_t j = i;
        while (p[j] == ' ') j++;
        while (p[j] && p[j] != ' ' && p[j] != '\n') j++;
        if (j >= sizeof buf || j == i) break;
        memcpy(buf, p, j);
        buf[j] = '\0';
        if (txt_width(cr, buf, size, bold) > maxw) break;
        best = j;
        i = j;
        if (!p[j] || p[j] == '\n') break;
    }
    if (best == 0) {                           /* słowo dłuższe niż wiersz */
        size_t j = 0, ok = 0;
        while (p[j] && p[j] != ' ' && p[j] != '\n') {
            size_t k = j + 1;
            while (((unsigned char)p[k] & 0xC0) == 0x80) k++;
            if (k >= sizeof buf) break;
            memcpy(buf, p, k);
            buf[k] = '\0';
            if (txt_width(cr, buf, size, bold) > maxw && ok > 0) break;
            ok = k;
            j = k;
        }
        best = ok ? ok : 1;
    }
    size_t n = best < outn - 1 ? best : outn - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    p += best;
    if (*p == '\n') p++;
    *pp = p;
    return 1;
}

double doc_wrap(doc_t *d, double x, double y, double maxw, const char *text, double size,
                int bold, rgb_t col, double lh, int draw)
{
    char line[2048];
    const char *p = text;
    double h = 0;
    while (next_line(d->cr, &p, maxw, size, bold, line, sizeof line)) {
        if (draw) txt_draw(d->cr, x, y + h + size, line, size, bold, col, AL_LEFT);
        h += lh;
    }
    return h;
}

void doc_par(doc_t *d, const char *text, double size, rgb_t col)
{
    char line[2048];
    const char *p = text;
    double lh = size * 1.42;
    while (next_line(d->cr, &p, doc_width(d), size, 0, line, sizeof line)) {
        doc_ensure(d, lh);
        txt_draw(d->cr, d->ml, d->y + size, line, size, 0, col, AL_LEFT);
        d->y += lh;
    }
    d->y += size * 0.6;
}

void doc_text(doc_t *d, const char *text) { doc_par(d, text, 9.5, C_INK); }
void doc_note(doc_t *d, const char *text) { doc_par(d, text, 8, C_INK2); }

void doc_bullet(doc_t *d, const char *text)
{
    char line[2048];
    const char *p = text;
    double size = 9.5, lh = size * 1.42, ind = 13;
    int first = 1;
    while (next_line(d->cr, &p, doc_width(d) - ind, size, 0, line, sizeof line)) {
        doc_ensure(d, lh);
        if (first) txt_draw(d->cr, d->ml + 2, d->y + size, "\xE2\x80\xA2", size, 0, C_INK2, AL_LEFT);
        txt_draw(d->cr, d->ml + ind, d->y + size, line, size, 0, C_INK, AL_LEFT);
        d->y += lh;
        first = 0;
    }
    d->y += 2.5;
}

/* ---- Nagłówki i spis treści ---- */

static void toc_add(doc_t *d, int level, const char *text)
{
    if (d->ntoc >= DOC_MAX_TOC) return;
    toc_entry_t *e = &d->toc[d->ntoc++];
    e->level = level;
    e->page = d->page;
    snprintf(e->title, sizeof e->title, "%s", text);
}

static void outline_add(doc_t *d, int level, const char *text)
{
#if HAVE_PDF_TAGS
    if (d->dry) return;
    char attr[96];
    snprintf(attr, sizeof attr, "page=%d pos=[%.1f %.1f]", d->page, d->ml, d->y > 20 ? d->y - 20 : 0);
    int parent = level == 1 ? CAIRO_PDF_OUTLINE_ROOT : d->outline_h1;
    int id = cairo_pdf_surface_add_outline(d->surf, parent, text, attr,
                                           level == 1 ? CAIRO_PDF_OUTLINE_FLAG_OPEN : 0);
    if (level == 1) d->outline_h1 = id;
#else
    (void)d; (void)level; (void)text;
#endif
}

void doc_h1(doc_t *d, const char *text)
{
    if (!(d->page > 0 && g_fresh)) doc_new_page(d, 1);
    g_fresh = 0;
    toc_add(d, 1, text);
    outline_add(d, 1, text);
    txt_draw(d->cr, d->ml, d->y + 18, text, 18, 1, C_INK, AL_LEFT);
    d->y += 30;
    set_rgb(d->cr, C_AXIS);
    cairo_set_line_width(d->cr, 0.8);
    cairo_move_to(d->cr, d->ml, d->y);
    cairo_line_to(d->cr, d->W - d->mr, d->y);
    cairo_stroke(d->cr);
    d->y += 14;
}

void doc_h2(doc_t *d, const char *text)
{
    doc_ensure(d, 90);
    if (d->y > d->mt + 1) d->y += 8;
    toc_add(d, 2, text);
    outline_add(d, 2, text);
    txt_draw(d->cr, d->ml, d->y + 12.5, text, 12.5, 1, C_INK, AL_LEFT);
    d->y += 22;
}

void doc_toc(doc_t *d)
{
    doc_h2(d, "Spis treści");
    d->ntoc--;                                /* spis nie wchodzi do spisu */
    d->y += 4;
    for (int i = 0; i < d->ntoc_ref; i++) {
        const toc_entry_t *e = &d->toc_ref[i];
        double size = e->level == 1 ? 10.5 : 9.5;
        int bold = e->level == 1;
        double x = d->ml + (e->level == 1 ? 0 : 16);
        double lh = e->level == 1 ? 20 : 15;
        if (e->level == 1 && i > 0) d->y += 3;
        doc_ensure(d, lh);
        char num[16];
        snprintf(num, sizeof num, "%d", e->page);
        double base = d->y + size + 2;
#if HAVE_PDF_TAGS
        char attr[48];
        snprintf(attr, sizeof attr, "page=%d", e->page);
        if (!d->dry) cairo_tag_begin(d->cr, CAIRO_TAG_LINK, attr);
#endif
        txt_draw(d->cr, x, base, e->title, size, bold, C_INK, AL_LEFT);
        double tw = txt_width(d->cr, e->title, size, bold);
        double nw = txt_width(d->cr, num, size, bold);
        double right = d->W - d->mr;
        /* kropki prowadzące */
        set_rgb(d->cr, C_AXIS);
        for (double dx = x + tw + 6; dx < right - nw - 6; dx += 4) {
            cairo_arc(d->cr, dx, base - 1.5, 0.55, 0, 6.2832);
            cairo_fill(d->cr);
        }
        txt_draw(d->cr, right, base, num, size, bold, C_INK, AL_RIGHT);
#if HAVE_PDF_TAGS
        if (!d->dry) cairo_tag_end(d->cr, CAIRO_TAG_LINK);
#endif
        d->y += lh;
    }
}

/* ---- Tabele ---- */

double doc_badge(cairo_t *cr, double x, double y, int sev, double size)
{
    static const char *const lab[3] = {"NISKI", "ŚREDNI", "WYSOKI"};
    if (sev < 0 || sev > 2) return 0;
    double w = txt_width(cr, lab[sev], size, 1) + 10;
    set_rgb(cr, C_SEV[sev]);
    round_rect(cr, x, y - size - 2.5, w, size + 6, 3);
    cairo_fill(cr);
    txt_draw(cr, x + 5, y, lab[sev], size, 1, C_SEV_TEXT[sev], AL_LEFT);
    return w;
}

void doc_kv(doc_t *d, const char *const *keys, const char *const *vals, int n)
{
    double rh = 15, size = 8.6;
    double kw = doc_width(d) * 0.46;
    for (int i = 0; i < n; i++) {
        doc_ensure(d, rh);
        if (i % 2 == 0) {
            set_rgb(d->cr, C_ZEBRA);
            cairo_rectangle(d->cr, d->ml, d->y, doc_width(d), rh);
            cairo_fill(d->cr);
        }
        char buf[512];
        txt_fit(d->cr, keys[i], size, 0, kw - 12, buf, sizeof buf);
        txt_draw(d->cr, d->ml + 6, d->y + rh - 4.5, buf, size, 0, C_INK2, AL_LEFT);
        txt_fit(d->cr, vals[i], size, 0, doc_width(d) - kw - 12, buf, sizeof buf);
        txt_draw(d->cr, d->ml + kw, d->y + rh - 4.5, buf, size, 0, C_INK, AL_LEFT);
        d->y += rh;
    }
    d->y += 10;
}

void table_init(table_t *t, int ncols)
{
    memset(t, 0, sizeof *t);
    t->ncols = ncols;
    t->badge_col = -1;
    t->font = 7.8;
    for (int i = 0; i < ncols; i++) t->w[i] = 1;
}

void table_col(table_t *t, int i, const char *head, double w, int align)
{
    t->head[i] = head;
    t->w[i] = w;
    t->align[i] = align;
}

void table_add(table_t *t, ...)
{
    if (t->nrows == t->cap) {
        t->cap = t->cap ? t->cap * 2 : 16;
        t->cells = xrealloc(t->cells, (size_t)t->cap * (size_t)t->ncols * sizeof *t->cells);
        t->sev = xrealloc(t->sev, (size_t)t->cap * sizeof *t->sev);
    }
    va_list ap;
    va_start(ap, t);
    for (int c = 0; c < t->ncols; c++) {
        const char *s = va_arg(ap, const char *);
        t->cells[(size_t)t->nrows * (size_t)t->ncols + (size_t)c] = xstrdup(s ? s : "");
    }
    va_end(ap);
    t->sev[t->nrows] = -1;
    t->nrows++;
}

void table_set_sev(table_t *t, int sev)
{
    if (t->nrows > 0) t->sev[t->nrows - 1] = sev;
}

void table_free(table_t *t)
{
    for (int i = 0; i < t->nrows * t->ncols; i++) free(t->cells[i]);
    free(t->cells);
    free(t->sev);
    memset(t, 0, sizeof *t);
}

static void table_header(doc_t *d, const table_t *t, const double *cx, const double *cw, double rh)
{
    for (int c = 0; c < t->ncols; c++) {
        char buf[128];
        txt_fit(d->cr, t->head[c] ? t->head[c] : "", t->font, 1, cw[c] - 8, buf, sizeof buf);
        double x = t->align[c] == AL_RIGHT ? cx[c] + cw[c] - 4 : cx[c] + 4;
        txt_draw(d->cr, x, d->y + rh - 5, buf, t->font, 1, C_INK2, t->align[c]);
    }
    d->y += rh;
    set_rgb(d->cr, C_AXIS);
    cairo_set_line_width(d->cr, 0.8);
    cairo_move_to(d->cr, d->ml, d->y);
    cairo_line_to(d->cr, d->W - d->mr, d->y);
    cairo_stroke(d->cr);
}

void doc_table(doc_t *d, const table_t *t, const char *caption)
{
    double rh = t->font * 2.0;
    double cx[12], cw[12], tot = 0;
    for (int c = 0; c < t->ncols; c++) tot += t->w[c];
    double x = d->ml;
    for (int c = 0; c < t->ncols; c++) {
        cx[c] = x;
        cw[c] = t->w[c] / tot * doc_width(d);
        x += cw[c];
    }
    double cap_h = caption ? 16 : 0;
    doc_ensure(d, cap_h + rh * (t->nrows > 2 ? 4 : t->nrows + 2));
    if (caption) {
        char buf[300];
        snprintf(buf, sizeof buf, "Tabela %d. %s", ++d->tab_no, caption);
        txt_draw(d->cr, d->ml, d->y + 9, buf, 8, 1, C_INK2, AL_LEFT);
        d->y += cap_h;
    }
    table_header(d, t, cx, cw, rh);
    for (int r = 0; r < t->nrows; r++) {
        if (d->y + rh > d->H - d->mb) {
            doc_new_page(d, 1);
            g_fresh = 0;
            table_header(d, t, cx, cw, rh);
        }
        if (r % 2 == 1) {
            set_rgb(d->cr, C_ZEBRA);
            cairo_rectangle(d->cr, d->ml, d->y, doc_width(d), rh);
            cairo_fill(d->cr);
        }
        for (int c = 0; c < t->ncols; c++) {
            const char *s = t->cells[(size_t)r * (size_t)t->ncols + (size_t)c];
            double base = d->y + rh - 5;
            if (c == t->badge_col && t->sev[r] >= 0) {
                doc_badge(d->cr, cx[c] + 4, base - 0.5, t->sev[r], t->font - 1.3);
                continue;
            }
            char buf[512];
            txt_fit(d->cr, s, t->font, 0, cw[c] - 8, buf, sizeof buf);
            double tx = t->align[c] == AL_RIGHT ? cx[c] + cw[c] - 4 : cx[c] + 4;
            txt_draw(d->cr, tx, base, buf, t->font, 0, C_INK, t->align[c]);
        }
        d->y += rh;
    }
    d->y += 12;
}

/* ---- Wykresy ---- */

void doc_figure(doc_t *d, const analysis_t *A, int id)
{
    double cw = doc_width(d);
    double fh = figure_height(A, id);
    double sc = cw / FIG_W;
    double h = fh * sc;
    doc_ensure(d, h + 24);
    cairo_t *cr = d->cr;
    cairo_save(cr);
    cairo_translate(cr, d->ml, d->y);
    cairo_scale(cr, sc, sc);
    cairo_rectangle(cr, 0, 0, FIG_W, fh);
    cairo_clip(cr);
    figure_draw(A, id, cr, FIG_W, fh);
    cairo_restore(cr);
    d->y += h + 4;
    char buf[300];
    if (figure_available(A, id))
        snprintf(buf, sizeof buf, "Rys. %d. %s (plik: wykresy/%s)", ++d->fig_no, figure_title(id),
                 figure_file(id));
    else
        snprintf(buf, sizeof buf, "Rys. %d. %s", ++d->fig_no, figure_title(id));
    txt_draw(cr, d->ml, d->y + 8, buf, 7.5, 0, C_MUTED, AL_LEFT);
    d->y += 22;
}
