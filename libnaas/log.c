#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include <vnet/error.h>

#include "log.h"
#include "strbuf.h"

static int g_naas_log_level = LOG_INFO;

static void
naas_err_vlogf(int level, naas_err_t err, const char *format, va_list ap)
{
	char log_buf[NAAS_LOGBUFSZ];
	struct naas_strbuf sb;

	if (g_naas_log_level < level) {
		return;
	}
	naas_strbuf_init(&sb, log_buf, sizeof(log_buf));
	naas_strbuf_vaddf(&sb, format, ap);
	naas_log_add_error(&sb, err);
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

static void
naas_log_add_vnet_error(struct naas_strbuf *sb, int err_num)
{
	switch (-err_num) {
#define _(a, b, c) \
	case b: \
		naas_strbuf_addf(sb, " (VNET_ERR_%s:%s)", #a, c); \
		break;
	foreach_vnet_error
#undef _

	default:
		naas_strbuf_addf(sb, "(VNET_ERR_%d:?)", -err_num);
		break;
	}
}

void
naas_log_add_errno(struct naas_strbuf *sb, int err_num)
{
	naas_strbuf_addf(sb, " (%d:%s)", err_num, strerror(err_num));
}

void
naas_log_add_error(struct naas_strbuf *sb, naas_err_t err)
{
	if (err.num) {
		switch (err.type) {
		case NAAS_ERR_VNET:
			naas_log_add_vnet_error(sb, err.num);
			break;
		default:
			naas_log_add_errno(sb, err.num);
			break;
		}
	}
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
naas_logf(int level, const char *format, ...)
{
	va_list ap;
	naas_err_t err;

	err.type = NAAS_ERR_ERRNO;
	err.num = 0;

	va_start(ap, format);
	naas_err_vlogf(level, err, format, ap);
	va_end(ap);
}

void
naas_err_logf(int level, naas_err_t err, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	naas_err_vlogf(level, err, format, ap);
	va_end(ap);
}

void
naas_errno_logf(int level, int err_num, const char *format, ...)
{
	va_list ap;
	naas_err_t err;

	err.type = NAAS_ERR_ERRNO;
	err.num = err_num;

	va_start(ap, format);
	naas_err_vlogf(level, err, format, ap);
	va_end(ap);
}
