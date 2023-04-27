#ifndef NAAS_COMMON_LOG_H
#define NAAS_COMMON_LOG_H

#include <syslog.h>
#include "utils.h"

#define NAAS_LOGBUFSZ 256

struct naas_strbuf;

void naas_set_log_level(int log_level);
int naas_get_log_level(void);
int naas_log_level_from_string(const char *s);
void naas_log_add_errno(struct naas_strbuf *sb, int err_num);
void naas_log_add_error(struct naas_strbuf *sb, naas_err_t err);
void naas_log_flush(int level, struct naas_strbuf *sb);
void naas_log_init(const char *ident, int options);

void naas_logf(int level, const char *format, ...)
	__attribute__((format(printf, 2, 3)));

void naas_err_logf(int level, naas_err_t err, const char *format, ...)
	__attribute__((format(printf, 3, 4)));

void naas_errno_logf(int level, int err_num, const char *format, ...)
	__attribute__((format(printf, 3, 4)));


#endif // NAAS_COMMON_LOG_H
