#ifndef PA_EXPORT_H
#define PA_EXPORT_H

#include "analysis.h"

int export_flows_csv(const analysis_t *A, const char *path);
int export_anomalies_csv(const analysis_t *A, const char *path);
int export_summary(const analysis_t *A, const char *path);

#endif
