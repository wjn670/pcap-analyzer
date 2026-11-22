#ifndef PA_REPORT_H
#define PA_REPORT_H

#include "analysis.h"

/* Zwraca liczbę stron raportu albo -1 przy błędzie. */
int report_write_pdf(const analysis_t *A, const char *path);

/* Znacznik czasu generowania (uwzględnia SOURCE_DATE_EPOCH dla powtarzalności). */
long long report_timestamp(void);

#endif
