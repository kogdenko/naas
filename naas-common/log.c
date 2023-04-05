#include <stdio.h>
#include <string.h>
#include <errno.h>
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
	naas_strbuf_vaddf(&sb, format, ap);
	if (errnum) {
		naas_log_add_error(&sb, errnum);
	}
	naas_log_flush(level, &sb);
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

int
naas_log_level_from_string(const char *s)
{
	if (!strcasecmp(s, "err")) {
		return LOG_ERR;
	} else if (!strcasecmp(s, "warning")) {
		return LOG_WARNING;
	} else if (!strcasecmp(s, "notice")) {
		return LOG_NOTICE;
	} else if (!strcasecmp(s, "info")) {
		return LOG_INFO;
	} else if (!strcasecmp(s, "debug")) {
		return LOG_DEBUG;
	} else {
		return -EINVAL;
	}
}

void
naas_log_add_error(struct naas_strbuf *sb, int errnum)
{
	naas_strbuf_addf(sb, " (%d:%s)", errnum, strerror(errnum));
}

void
naas_log_flush(int level, struct naas_strbuf *sb)
{
	const char *s;

	s = naas_strbuf_cstr(sb);
	syslog(level, "%s", s);
	printf("%s\n", s);
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
