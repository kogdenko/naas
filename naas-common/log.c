#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "log.h"
#include "strbuf.h"

static int g_naas_log_level = LOG_INFO;

static void
naas_vlogf(int level, int errnum, const char *format, va_list ap)
{
	char log_buf[NAAS_LOGBUFSZ];
	struct naas_strbuf sb;

	if (g_naas_log_level < level) {
		return;
	}
	naas_strbuf_init(&sb, log_buf, sizeof(log_buf));
	if (errnum) {
		naas_log_add_error(&sb, errnum);
		naas_log_flush(level, &sb);
	} else {
		vsyslog(level, format, ap);
	}
}

void
naas_set_log_level(int log_level)
{
	g_naas_log_level = log_level;
}

int
naas_get_log_level(void)
{
	return g_naas_log_level;
}

void
naas_log_add_error(struct naas_strbuf *sb, int errnum)
{
	naas_strbuf_addf(sb, " (%d:%s)", errnum, strerror(errnum));
}

void
naas_log_flush(int level, struct naas_strbuf *sb)
{
	syslog(level, "%s", naas_strbuf_cstr(sb));
}

void
naas_log_init(const char *ident, int options)
{
	openlog(ident, options, LOG_DAEMON);
	naas_logf(naas_get_log_level(), 0, "Logging started");
}

void
naas_logf(int level, int errnum, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	naas_vlogf(level, errnum, format, ap);
	va_end(ap);
}
