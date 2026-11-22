#include "chart.h"
#include "util.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#define HEX(h) { (((h) >> 16) & 0xff) / 255.0, (((h) >> 8) & 0xff) / 255.0, ((h) & 0xff) / 255.0 }

/* kolory serii, zawsze w tej kolejności */
const rgb_t C_SERIES[8] = {HEX(0x2a78d6), HEX(0xeb6834), HEX(0x1baf7a), HEX(0xeda100),
                           HEX(0xe87ba4), HEX(0x008300), HEX(0x6250d6), HEX(0xe34948)};
const rgb_t C_SURFACE = HEX(0xfcfcfb);
const rgb_t C_PAGE    = HEX(0xffffff);
const rgb_t C_INK     = HEX(0x0b0b0b);
const rgb_t C_INK2    = HEX(0x52514e);
const rgb_t C_MUTED   = HEX(0x898781);
const rgb_t C_GRID    = HEX(0xe1e0d9);
const rgb_t C_AXIS    = HEX(0xc3c2b7);
const rgb_t C_WHITE   = HEX(0xffffff);
/* kolory poziomów ważności: niski, średni, wysoki */
const rgb_t C_SEV[3]      = {HEX(0xfab219), HEX(0xec835a), HEX(0xd03b3b)};
const rgb_t C_SEV_TEXT[3] = {HEX(0x0b0b0b), HEX(0xffffff), HEX(0xffffff)};

/* wymiary w punktach, PNG jest potem skalowany x2 */
#define PAD        16.0
#define TITLE_SZ   15.0
#define SUB_SZ     11.0
#define LABEL_SZ   10.5
#define LEGEND_SZ  11.0
#define BAR_MAX    22.0
#define BAR_R      4.0
#define GAP        2.0

static char g_font[96] = "sans-serif";

void chart_set_font(const char *family)
{
    if (family && *family) snprintf(g_font, sizeof g_font, "%s", family);
}

const char *chart_get_font(void) { return g_font; }

void set_rgb(cairo_t *cr, rgb_t c) { cairo_set_source_rgb(cr, c.r, c.g, c.b); }
void set_rgba(cairo_t *cr, rgb_t c, double a) { cairo_set_source_rgba(cr, c.r, c.g, c.b, a); }

/* ---- Tekst ---- */

void txt_font(cairo_t *cr, double size, int bold)
{
    cairo_select_font_face(cr, g_font, CAIRO_FONT_SLANT_NORMAL,
                           bold ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, size);
}

double txt_width(cairo_t *cr, const char *s, double size, int bold)
{
    cairo_text_extents_t e;
    txt_font(cr, size, bold);
    cairo_text_extents(cr, s, &e);
    return e.x_advance;
}

void txt_draw(cairo_t *cr, double x, double y, const char *s, double size, int bold,
              rgb_t col, int align)
{
    if (!s || !*s) return;
    double w = align != AL_LEFT ? txt_width(cr, s, size, bold) : 0;
    txt_font(cr, size, bold);
    set_rgb(cr, col);
    if (align == AL_CENTER) x -= w / 2;
    else if (align == AL_RIGHT) x -= w;
    cairo_move_to(cr, x, y);
    cairo_show_text(cr, s);
    cairo_new_path(cr);
}

void txt_fit(cairo_t *cr, const char *s, double size, int bold, double maxw, char *out, size_t outlen)
{
    snprintf(out, outlen, "%s", s);
    if (txt_width(cr, out, size, bold) <= maxw) return;
    size_t len = strlen(out);
    while (len > 0) {
        /* cofnięcie o jeden znak UTF-8 */
        do { len--; } while (len > 0 && ((unsigned char)out[len] & 0xC0) == 0x80);
        if (len + 4 > outlen) continue;
        memcpy(out + len, "\xE2\x80\xA6", 4);   /* "…" + NUL */
        if (txt_width(cr, out, size, bold) <= maxw) return;
    }
    snprintf(out, outlen, "\xE2\x80\xA6");
}

/* ---- Kształty ---- */

void round_rect(cairo_t *cr, double x, double y, double w, double h, double r)
{
    if (r > w / 2) r = w / 2;
    if (r > h / 2) r = h / 2;
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r, r, -M_PI / 2, 0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0, M_PI / 2);
    cairo_arc(cr, x + r, y + h - r, r, M_PI / 2, M_PI);
    cairo_arc(cr, x + r, y + r, r, M_PI, 3 * M_PI / 2);
    cairo_close_path(cr);
}

/* Słupek z zaokrąglonym końcem danych i prostym końcem przy linii bazowej. */
static void bar_right(cairo_t *cr, double x, double y, double w, double h, double r)
{
    if (r > w) r = w;
    if (r > h / 2) r = h / 2;
    cairo_new_sub_path(cr);
    cairo_move_to(cr, x, y);
    cairo_line_to(cr, x + w - r, y);
    cairo_arc(cr, x + w - r, y + r, r, -M_PI / 2, 0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0, M_PI / 2);
    cairo_line_to(cr, x, y + h);
    cairo_close_path(cr);
}

static void bar_up(cairo_t *cr, double x, double ybase, double w, double h, double r)
{
    if (r > h) r = h;
    if (r > w / 2) r = w / 2;
    double top = ybase - h;
    cairo_new_sub_path(cr);
    cairo_move_to(cr, x, ybase);
    cairo_line_to(cr, x, top + r);
    cairo_arc(cr, x + r, top + r, r, M_PI, 3 * M_PI / 2);
    cairo_arc(cr, x + w - r, top + r, r, 3 * M_PI / 2, 2 * M_PI);
    cairo_line_to(cr, x + w, ybase);
    cairo_close_path(cr);
}

static void hline(cairo_t *cr, double x0, double x1, double y, rgb_t c)
{
    y = floor(y) + 0.0;
    set_rgb(cr, c);
    cairo_set_line_width(cr, 1.0);
    cairo_move_to(cr, x0, y);
    cairo_line_to(cr, x1, y);
    cairo_stroke(cr);
}

static void vline(cairo_t *cr, double x, double y0, double y1, rgb_t c)
{
    x = floor(x);
    set_rgb(cr, c);
    cairo_set_line_width(cr, 1.0);
    cairo_move_to(cr, x, y0);
    cairo_line_to(cr, x, y1);
    cairo_stroke(cr);
}

/* ---- Formatowanie etykiet osi ---- */

static void comma(char *s)
{
    for (; *s; s++)
        if (*s == '.') *s = ',';
}

static const char *si_short(double v, const char *unit)
{
    static char buf[16][32];
    static int k;
    k = (k + 1) & 15;
    if (v == 0) { snprintf(buf[k], sizeof buf[k], "0"); return buf[k]; }
    static const char *const pre[] = {"", "k", "M", "G", "T", "P"};
    int i = 0;
    double a = fabs(v);
    while (a >= 999.5 && i < 5) { a /= 1000; v /= 1000; i++; }
    snprintf(buf[k], sizeof buf[k], "%.3g\xC2\xA0%s%s", v, pre[i], unit);
    comma(buf[k]);
    return buf[k];
}

static const char *dur_short(double s)
{
    static char buf[16][32];
    static int k;
    k = (k + 1) & 15;
    if (s <= 0) snprintf(buf[k], sizeof buf[k], "0");
    else if (s < 1e-3) snprintf(buf[k], sizeof buf[k], "%.3g\xC2\xA0µs", s * 1e6);
    else if (s < 1) snprintf(buf[k], sizeof buf[k], "%.3g\xC2\xA0ms", s * 1e3);
    else if (s < 60) snprintf(buf[k], sizeof buf[k], "%.3g\xC2\xA0s", s);
    else if (s < 3600) snprintf(buf[k], sizeof buf[k], "%.3g\xC2\xA0min", s / 60);
    else if (s < 86400 * 2) snprintf(buf[k], sizeof buf[k], "%.3g\xC2\xA0h", s / 3600);
    else snprintf(buf[k], sizeof buf[k], "%.3g\xC2\xA0" "d", s / 86400);
    comma(buf[k]);
    return buf[k];
}

const char *fmt_value(double v, valfmt_t f)
{
    switch (f) {
    case VF_BYTES: return si_short(v, "B");
    case VF_BITRATE: return si_short(v, "b/s");
    case VF_DUR: return dur_short(v);
    case VF_PCT: {
        static char buf[8][24];
        static int k;
        k = (k + 1) & 7;
        double p = v * 100;
        if (p == 0 || p >= 10 || fabs(p - round(p)) < 1e-9) snprintf(buf[k], sizeof buf[k], "%.0f%%", p);
        else snprintf(buf[k], sizeof buf[k], "%.1f%%", p);
        comma(buf[k]);
        return buf[k];
    }
    case VF_NUM:
    default: return fmt_compact(v);
    }
}

/* ---- Osie i skale ---- */

static double nice_num(double x, int round_it)
{
    if (x <= 0) return 1;
    double e = floor(log10(x));
    double f = x / pow(10, e), nf;
    if (round_it) nf = f < 1.5 ? 1 : f < 3 ? 2 : f < 7 ? 5 : 10;
    else nf = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10;
    return nf * pow(10, e);
}

/* Podziałka od 0 do "ładnej" wartości >= maxv. Zwraca liczbę znaczników. */
static int y_ticks(double maxv, double *t, int maxn, double *top)
{
    if (!(maxv > 0)) maxv = 1;
    double step = nice_num(nice_num(maxv, 0) / 4.0, 1);
    double hi = ceil(maxv / step - 1e-9) * step;
    int n = 0;
    for (double v = 0; v <= hi + step * 0.5 && n < maxn; v += step) t[n++] = v;
    *top = hi;
    return n;
}

static double time_step(double range, int target)
{
    static const double s[] = {0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5,
                               10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800,
                               21600, 43200, 86400, 172800, 604800};
    for (size_t i = 0; i < ARRAY_LEN(s); i++)
        if (range / s[i] <= target) return s[i];
    return s[ARRAY_LEN(s) - 1];
}

static void time_label(double t, double range, double step, char *buf, size_t n)
{
    if (range < 120) {
        int dec = step < 0.01 ? 3 : step < 0.1 ? 2 : step < 1 ? 1 : 0;
        snprintf(buf, n, "%.*f", dec, t);
        comma(buf);
    } else if (range < 7200) {
        long s = lround(t);
        snprintf(buf, n, "%ld:%02ld", s / 60, s % 60);
    } else {
        long m = lround(t / 60);
        snprintf(buf, n, "%ld:%02ld", m / 60, m % 60);
    }
}

static const char *time_axis_title(double range)
{
    if (range < 120) return "Czas od początku zrzutu [s]";
    if (range < 7200) return "Czas od początku zrzutu [min:s]";
    return "Czas od początku zrzutu [h:min]";
}

/* ---- Nagłówek wykresu: tło, tytuł, podtytuł, legenda ---- */

typedef struct {
    const char *name;
    rgb_t color;
    int line;        /* klucz liniowy zamiast kwadratu */
} legend_item_t;

static double draw_legend(cairo_t *cr, double x, double y, double maxx,
                          const legend_item_t *it, int n)
{
    double cx = x;
    for (int i = 0; i < n; i++) {
        double w = txt_width(cr, it[i].name, LEGEND_SZ, 0) + 16 + 18;
        if (cx + w > maxx && cx > x) { cx = x; y += 17; }
        if (it[i].line) {
            set_rgb(cr, it[i].color);
            cairo_set_line_width(cr, 2.5);
            cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
            cairo_move_to(cr, cx, y - 4);
            cairo_line_to(cr, cx + 12, y - 4);
            cairo_stroke(cr);
        } else {
            set_rgb(cr, it[i].color);
            round_rect(cr, cx, y - 9.5, 10, 10, 2);
            cairo_fill(cr);
        }
        txt_draw(cr, cx + 16, y, it[i].name, LEGEND_SZ, 0, C_INK2, AL_LEFT);
        cx += w;
    }
    return y;
}

/* Zwraca współrzędną y początku obszaru wykresu. */
static double header(cairo_t *cr, double W, double H, const chart_spec_t *s,
                     const legend_item_t *leg, int nleg)
{
    set_rgb(cr, C_SURFACE);
    cairo_rectangle(cr, 0, 0, W, H);
    cairo_fill(cr);

    double y = PAD + 12;
    char buf[256];
    txt_fit(cr, s->title ? s->title : "", TITLE_SZ, 1, W - 2 * PAD, buf, sizeof buf);
    txt_draw(cr, PAD, y, buf, TITLE_SZ, 1, C_INK, AL_LEFT);
    if (s->subtitle && *s->subtitle) {
        y += 17;
        txt_fit(cr, s->subtitle, SUB_SZ, 0, W - 2 * PAD, buf, sizeof buf);
        txt_draw(cr, PAD, y, buf, SUB_SZ, 0, C_INK2, AL_LEFT);
    }
    if (nleg > 0) {
        y += 20;
        y = draw_legend(cr, PAD, y, W - PAD, leg, nleg);
    }
    return y + 16;
}

static int series_legend(const chart_spec_t *s, legend_item_t *leg, int line)
{
    if (s->nseries < 2) return 0;
    for (int i = 0; i < s->nseries; i++) {
        leg[i].name = s->names[i];
        leg[i].color = s->colors[i];
        leg[i].line = line;
    }
    return s->nseries;
}

/* Oś Y z siatką; zwraca lewą krawędź obszaru wykresu. */
static double y_axis(cairo_t *cr, const chart_spec_t *s, const double *ticks, int nt,
                     double top, double ybot, double ytop, double right, valfmt_t yf)
{
    double maxw = 0;
    for (int i = 0; i < nt; i++) {
        double w = txt_width(cr, fmt_value(ticks[i], yf), LABEL_SZ, 0);
        if (w > maxw) maxw = w;
    }
    double left = PAD + (s->ylabel ? 18 : 0) + maxw + 8;
    for (int i = 0; i < nt; i++) {
        double y = ybot - ticks[i] / top * (ybot - ytop);
        hline(cr, left, right, y, i == 0 ? C_AXIS : C_GRID);
        txt_draw(cr, left - 6, floor(y) + 3.5, fmt_value(ticks[i], yf), LABEL_SZ, 0, C_MUTED, AL_RIGHT);
    }
    if (s->ylabel) {
        cairo_save(cr);
        cairo_translate(cr, PAD + 9, (ybot + ytop) / 2);
        cairo_rotate(cr, -M_PI / 2);
        txt_draw(cr, 0, 0, s->ylabel, LABEL_SZ, 0, C_MUTED, AL_CENTER);
        cairo_restore(cr);
    }
    return left;
}

static void time_x_axis(cairo_t *cr, double left, double right, double ybot, double H, double xmax)
{
    double range = xmax > 0 ? xmax : 1;
    double step = time_step(range, (int)((right - left) / 80));
    char buf[32];
    for (double t = 0; t <= range + 1e-9; t += step) {
        double x = left + t / range * (right - left);
        time_label(t, range, step, buf, sizeof buf);
        set_rgb(cr, C_AXIS);
        cairo_set_line_width(cr, 1);
        cairo_move_to(cr, floor(x), ybot);
        cairo_line_to(cr, floor(x), ybot + 4);
        cairo_stroke(cr);
        txt_draw(cr, x, ybot + 17, buf, LABEL_SZ, 0, C_MUTED, AL_CENTER);
    }
    txt_draw(cr, (left + right) / 2, H - 8, time_axis_title(range), LABEL_SZ, 0, C_MUTED, AL_CENTER);
}

/* ---- Wykres liniowy (szereg czasowy) ---- */

void chart_lines(cairo_t *cr, double W, double H, const chart_spec_t *s,
                 const double *x, const double *const *y, int n, double xmax,
                 valfmt_t yf, const double *bands, int nbands)
{
    legend_item_t leg[10];
    int nleg = series_legend(s, leg, 1);
    if (nbands > 0) {
        if (nleg == 0 && s->nseries == 1) { leg[0] = (legend_item_t){s->names[0], s->colors[0], 1}; nleg = 1; }
        leg[nleg++] = (legend_item_t){"wykryty skok ruchu", C_SEV[0], 0};
    }
    double top = header(cr, W, H, s, leg, nleg);
    double bot = H - 40, right = W - PAD - 4;

    double maxv = 0;
    for (int k = 0; k < s->nseries; k++)
        for (int i = 0; i < n; i++)
            if (y[k][i] > maxv) maxv = y[k][i];
    double ticks[16], ytop;
    int nt = y_ticks(maxv, ticks, 16, &ytop);
    double left = y_axis(cr, s, ticks, nt, ytop, bot, top, right, yf);
    double range = xmax > 0 ? xmax : 1;
#define PX(v) (left + (v) / range * (right - left))
#define PY(v) (bot - (v) / ytop * (bot - top))

    cairo_save(cr);
    cairo_rectangle(cr, left, top - 2, right - left, bot - top + 2);
    cairo_clip(cr);
    for (int b = 0; b < nbands; b++) {
        double x0 = PX(bands[2 * b]), x1 = PX(bands[2 * b + 1]);
        if (x1 - x0 < 3) { x0 -= 1.5; x1 += 1.5; }
        set_rgba(cr, C_SEV[0], 0.22);
        cairo_rectangle(cr, x0, top, x1 - x0, bot - top);
        cairo_fill(cr);
    }
    cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
    cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
    for (int k = 0; k < s->nseries; k++) {
        if (n <= 0) break;
        /* wypełnienie o niskim kryciu */
        cairo_move_to(cr, PX(x[0]), bot);
        for (int i = 0; i < n; i++) cairo_line_to(cr, PX(x[i]), PY(y[k][i]));
        cairo_line_to(cr, PX(x[n - 1]), bot);
        cairo_close_path(cr);
        set_rgba(cr, s->colors[k], 0.10);
        cairo_fill(cr);
    }
    for (int k = 0; k < s->nseries; k++) {
        if (n <= 0) break;
        if (n == 1) {
            set_rgb(cr, s->colors[k]);
            cairo_arc(cr, PX(x[0]), PY(y[k][0]), 4, 0, 2 * M_PI);
            cairo_fill(cr);
            continue;
        }
        cairo_move_to(cr, PX(x[0]), PY(y[k][0]));
        for (int i = 1; i < n; i++) cairo_line_to(cr, PX(x[i]), PY(y[k][i]));
        set_rgb(cr, s->colors[k]);
        cairo_set_line_width(cr, n > 400 ? 1.5 : 2.0);
        cairo_stroke(cr);
    }
    cairo_restore(cr);
#undef PX
#undef PY
    time_x_axis(cr, left, right, bot, H, xmax);
}

/* ---- Ranking - poziome słupki ---- */

void chart_hbar(cairo_t *cr, double W, double H, const chart_spec_t *s,
                const char *const *labels, const double *const *vals, int n, valfmt_t vf)
{
    legend_item_t leg[8];
    int nleg = series_legend(s, leg, 0);
    double top = header(cr, W, H, s, leg, nleg);
    double bot = H - PAD;
    if (n <= 0) return;

    double maxtot = 0, labw = 0, valw = 0;
    for (int i = 0; i < n; i++) {
        double t = 0;
        for (int k = 0; k < s->nseries; k++) t += vals[k][i];
        if (t > maxtot) maxtot = t;
        double w = txt_width(cr, labels[i], LABEL_SZ + 0.5, 0);
        if (w > labw) labw = w;
        w = txt_width(cr, fmt_value(t, vf), LABEL_SZ, 0);
        if (w > valw) valw = w;
    }
    if (labw > W * 0.36) labw = W * 0.36;
    if (maxtot <= 0) maxtot = 1;
    double x0 = PAD + labw + 12;
    double x1 = W - PAD - valw - 10;
    double row = (bot - top) / n;
    if (row > 30) row = 30;
    double bh = row * 0.62;
    if (bh > BAR_MAX) bh = BAR_MAX;

    for (int i = 0; i < n; i++) {
        double cy = top + row * (i + 0.5);
        char buf[160];
        txt_fit(cr, labels[i], LABEL_SZ + 0.5, 0, labw, buf, sizeof buf);
        txt_draw(cr, PAD, cy + 4, buf, LABEL_SZ + 0.5, 0, C_INK2, AL_LEFT);

        double x = x0, total = 0;
        int last = -1;
        for (int k = 0; k < s->nseries; k++)
            if (vals[k][i] > 0) last = k;
        for (int k = 0; k < s->nseries; k++) {
            double v = vals[k][i];
            if (v <= 0) continue;
            total += v;
            double w = v / maxtot * (x1 - x0);
            double draw_w = (k == last) ? w : w - GAP;
            if (draw_w < 1) draw_w = 1;
            set_rgb(cr, s->colors[k]);
            if (k == last) bar_right(cr, x, cy - bh / 2, draw_w, bh, BAR_R);
            else cairo_rectangle(cr, x, cy - bh / 2, draw_w, bh);
            cairo_fill(cr);
            x += w;
        }
        txt_draw(cr, x + 6, cy + 4, fmt_value(total, vf), LABEL_SZ, 0, C_INK2, AL_LEFT);
    }
    vline(cr, x0, top, top + row * n, C_AXIS);
}

/* ---- Słupki pionowe ---- */

void chart_columns(cairo_t *cr, double W, double H, const chart_spec_t *s,
                   const char *const *labels, const double *const *vals, int n,
                   valfmt_t yf, int show_values)
{
    legend_item_t leg[8];
    int nleg = series_legend(s, leg, 0);
    double top = header(cr, W, H, s, leg, nleg);
    double bot = H - (s->xlabel ? 44 : 30), right = W - PAD - 4;
    if (show_values) top += 10;
    if (n <= 0) return;

    double maxv = 0;
    for (int k = 0; k < s->nseries; k++)
        for (int i = 0; i < n; i++)
            if (vals[k][i] > maxv) maxv = vals[k][i];
    double ticks[16], ytop;
    int nt = y_ticks(maxv, ticks, 16, &ytop);
    double left = y_axis(cr, s, ticks, nt, ytop, bot, top, right, yf);

    double slot = (right - left) / n;
    int ns = s->nseries;
    double bw = (slot * 0.78 - (ns - 1) * GAP) / ns;
    if (bw > BAR_MAX + 2) bw = BAR_MAX + 2;
    if (bw < 1) bw = 1;
    double gw = ns * bw + (ns - 1) * GAP;

    double maxlw = 0;
    for (int i = 0; i < n; i++) {
        double w = txt_width(cr, labels[i], LABEL_SZ, 0);
        if (w > maxlw) maxlw = w;
    }
    int every = (int)ceil((maxlw + 8) / slot);
    if (every < 1) every = 1;

    for (int i = 0; i < n; i++) {
        double gx = left + slot * i + (slot - gw) / 2;
        for (int k = 0; k < ns; k++) {
            double v = vals[k][i];
            double h = v / ytop * (bot - top);
            double bx = gx + k * (bw + GAP);
            if (h > 0) {
                if (h < 1) h = 1;
                set_rgb(cr, s->colors[k]);
                bar_up(cr, bx, bot, bw, h, BAR_R);
                cairo_fill(cr);
            }
            if (show_values && v > 0)
                txt_draw(cr, bx + bw / 2, bot - h - 5, fmt_value(v, yf), LABEL_SZ - 0.5, 0, C_INK2, AL_CENTER);
        }
        if (i % every == 0)
            txt_draw(cr, left + slot * (i + 0.5), bot + 15, labels[i], LABEL_SZ, 0, C_MUTED, AL_CENTER);
    }
    hline(cr, left, right, bot, C_AXIS);
    if (s->xlabel) txt_draw(cr, (left + right) / 2, H - 8, s->xlabel, LABEL_SZ, 0, C_MUTED, AL_CENTER);
}

/* ---- Dystrybuanta (oś X logarytmiczna) ---- */

void chart_cdf(cairo_t *cr, double W, double H, const chart_spec_t *s,
               const double *const *sorted, const size_t *counts, valfmt_t xf, double xfloor)
{
    legend_item_t leg[8];
    int nleg = series_legend(s, leg, 1);
    double top = header(cr, W, H, s, leg, nleg);
    double bot = H - 40, right = W - PAD - 4;

    double mn = INFINITY, mx = 0;
    for (int k = 0; k < s->nseries; k++) {
        if (!counts[k]) continue;
        double lo = sorted[k][0] > xfloor ? sorted[k][0] : xfloor;
        if (lo < mn) mn = lo;
        if (sorted[k][counts[k] - 1] > mx) mx = sorted[k][counts[k] - 1];
    }
    if (!(mx > 0) || !isfinite(mn)) { mn = xfloor; mx = xfloor * 10; }
    if (mx < mn) mx = mn;
    double llo = floor(log10(mn)), lhi = ceil(log10(mx));
    if (lhi <= llo) lhi = llo + 1;

    double ticks[5] = {0, 0.25, 0.5, 0.75, 1.0};
    double left = y_axis(cr, s, ticks, 5, 1.0, bot, top, right, VF_PCT);
#define LX(v) (left + (log10((v) > xfloor ? (v) : xfloor) - llo) / (lhi - llo) * (right - left))
#define LY(q) (bot - (q) * (bot - top))

    int dec = (int)(lhi - llo);
    int every = dec > 8 ? 2 : 1;
    for (int d = 0; d <= dec; d++) {
        double v = pow(10, llo + d);
        double x = left + (double)d / dec * (right - left);
        if (d > 0) vline(cr, x, top, bot, C_GRID);
        if (d % every == 0) txt_draw(cr, x, bot + 17, fmt_value(v, xf), LABEL_SZ, 0, C_MUTED, AL_CENTER);
    }
    if (s->xlabel) txt_draw(cr, (left + right) / 2, H - 8, s->xlabel, LABEL_SZ, 0, C_MUTED, AL_CENTER);

    cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
    for (int k = 0; k < s->nseries; k++) {
        size_t n = counts[k];
        if (!n) continue;
        const double *v = sorted[k];
        if (n <= 2000) {
            cairo_move_to(cr, LX(v[0]), LY(0));
            for (size_t i = 0; i < n; i++) {
                cairo_line_to(cr, LX(v[i]), LY((double)i / n));
                cairo_line_to(cr, LX(v[i]), LY((double)(i + 1) / n));
            }
        } else {
            const int K = 1000;
            cairo_move_to(cr, LX(v[0]), LY(0));
            for (int i = 0; i <= K; i++) {
                double q = (double)i / K;
                cairo_line_to(cr, LX(quantile_sorted(v, n, q)), LY(q));
            }
        }
        cairo_line_to(cr, right, LY(1));
        set_rgb(cr, s->colors[k]);
        cairo_set_line_width(cr, 2);
        cairo_stroke(cr);
    }
    /* znacznik mediany */
    for (int k = 0; k < s->nseries; k++) {
        if (!counts[k]) continue;
        double med = quantile_sorted(sorted[k], counts[k], 0.5);
        double x = LX(med), y = LY(0.5);
        set_rgb(cr, C_SURFACE);
        cairo_arc(cr, x, y, 6, 0, 2 * M_PI);
        cairo_fill(cr);
        set_rgb(cr, s->colors[k]);
        cairo_arc(cr, x, y, 4, 0, 2 * M_PI);
        cairo_fill(cr);
        char buf[64];
        snprintf(buf, sizeof buf, "mediana %s", fmt_value(med, xf));
        double ly = k == 0 ? y - 9 : y + 17 + (k - 1) * 13;
        int al = x > right - 120 ? AL_RIGHT : AL_LEFT;
        txt_draw(cr, al == AL_LEFT ? x + 8 : x - 8, ly, buf, LABEL_SZ, 0, C_INK2, al);
    }
#undef LX
#undef LY
}

/* ---- Słupki segmentowe (udział w całości) ---- */

static int needs_dark_text(rgb_t c)
{
    double l = 0.2126 * c.r + 0.7152 * c.g + 0.0722 * c.b;
    return l > 0.55;
}

void chart_segbars(cairo_t *cr, double W, double H, const chart_spec_t *s,
                   const char *const *rows, const double *const *vals, int nrows)
{
    /* za wąski segment - procent idzie do legendy */
    char legtxt[8][96];
    legend_item_t leg[8];
    int ns = s->nseries;
    double labw = 0;
    for (int r = 0; r < nrows; r++) {
        double w = txt_width(cr, rows[r], LABEL_SZ + 0.5, 0);
        if (w > labw) labw = w;
    }
    double x0 = PAD + labw + 14, x1 = W - PAD;
    for (int k = 0; k < ns; k++) {
        int narrow = 0;
        char shares[64] = "";
        for (int r = 0; r < nrows; r++) {
            double tot = 0;
            for (int j = 0; j < ns; j++) tot += vals[r][j];
            double frac = tot > 0 ? vals[r][k] / tot : 0;
            const char *p = fmt_value(frac, VF_PCT);
            double bw = frac * (x1 - x0);
            if (frac > 0 && txt_width(cr, p, LABEL_SZ, 1) + 12 > bw) narrow = 1;
            size_t L = strlen(shares);
            snprintf(shares + L, sizeof shares - L, "%s%s", r ? " / " : "", p);
        }
        if (narrow) snprintf(legtxt[k], sizeof legtxt[k], "%s (%s)", s->names[k], shares);
        else snprintf(legtxt[k], sizeof legtxt[k], "%s", s->names[k]);
        leg[k] = (legend_item_t){legtxt[k], s->colors[k], 0};
    }
    double top = header(cr, W, H, s, leg, ns);
    double bh = 28;
    double row = (H - PAD - top) / (nrows > 0 ? nrows : 1);
    if (row > 56) row = 56;

    for (int r = 0; r < nrows; r++) {
        double cy = top + row * (r + 0.5);
        txt_draw(cr, PAD, cy + 4, rows[r], LABEL_SZ + 0.5, 0, C_INK2, AL_LEFT);
        double tot = 0;
        for (int k = 0; k < ns; k++) tot += vals[r][k];
        if (tot <= 0) continue;
        double x = x0;
        for (int k = 0; k < ns; k++) {
            double frac = vals[r][k] / tot;
            double w = frac * (x1 - x0);
            if (w <= 0) continue;
            double dw = w - GAP;
            if (dw < 1) dw = 1;
            set_rgb(cr, s->colors[k]);
            round_rect(cr, x, cy - bh / 2, dw, bh, BAR_R);
            cairo_fill(cr);
            const char *p = fmt_value(frac, VF_PCT);
            if (txt_width(cr, p, LABEL_SZ, 1) + 12 <= dw)
                txt_draw(cr, x + 6, cy + 4, p, LABEL_SZ, 1,
                         needs_dark_text(s->colors[k]) ? C_INK : C_WHITE, AL_LEFT);
            x += w;
        }
    }
}

/* ---- Oś czasu nieprawidłowości ---- */

void chart_gantt(cairo_t *cr, double W, double H, const chart_spec_t *s,
                 const gantt_item_t *items, int n, double tmax)
{
    static const char *const sev_names[3] = {"niski", "średni", "wysoki"};
    legend_item_t leg[3];
    for (int i = 0; i < 3; i++) leg[i] = (legend_item_t){sev_names[2 - i], C_SEV[2 - i], 0};
    double top = header(cr, W, H, s, leg, 3);
    double bot = H - 40, right = W - PAD - 4;
    if (n <= 0) return;

    double labw = 0;
    for (int i = 0; i < n; i++) {
        double w = txt_width(cr, items[i].label, LABEL_SZ, 0);
        if (w > labw) labw = w;
    }
    if (labw > W * 0.42) labw = W * 0.42;
    double left = PAD + labw + 12;
    double range = tmax > 0 ? tmax : 1;
    double step = time_step(range, (int)((right - left) / 80));
    for (double t = step; t <= range + 1e-9; t += step)
        vline(cr, left + t / range * (right - left), top, bot, C_GRID);

    double row = (bot - top) / n;
    if (row > 26) row = 26;
    double bh = row * 0.6;
    if (bh > 14) bh = 14;
    for (int i = 0; i < n; i++) {
        double cy = top + row * (i + 0.5);
        char buf[160];
        txt_fit(cr, items[i].label, LABEL_SZ, 0, labw, buf, sizeof buf);
        txt_draw(cr, PAD, cy + 4, buf, LABEL_SZ, 0, C_INK2, AL_LEFT);
        double xa = left + items[i].t0 / range * (right - left);
        double xb = left + items[i].t1 / range * (right - left);
        if (xb - xa < 5) { double c = (xa + xb) / 2; xa = c - 2.5; xb = c + 2.5; }
        if (xa < left) xa = left;
        int sv = items[i].sev < 0 ? 0 : items[i].sev > 2 ? 2 : items[i].sev;
        set_rgb(cr, C_SEV[sv]);
        round_rect(cr, xa, cy - bh / 2, xb - xa, bh, 3);
        cairo_fill(cr);
    }
    vline(cr, left, top, bot, C_AXIS);
    hline(cr, left, right, bot, C_AXIS);
    time_x_axis(cr, left, right, bot, H, tmax);
}

void chart_empty(cairo_t *cr, double W, double H, const chart_spec_t *s, const char *msg)
{
    double top = header(cr, W, H, s, NULL, 0);
    txt_draw(cr, W / 2, (top + H) / 2, msg, 13, 0, C_MUTED, AL_CENTER);
}
