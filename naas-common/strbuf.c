#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "utils.h"
#include "strbuf.h"

void
naas_strbuf_init(struct naas_strbuf *sb, char *buf, int bufsz)
{
	assert(bufsz);
	sb->sb_buf = buf;
	sb->sb_cap = bufsz;
	sb->sb_len = 0;
}

char *
naas_strbuf_cstr(struct naas_strbuf *sb)
{
	sb->sb_buf[sb->sb_len < sb->sb_cap ? sb->sb_len : sb->sb_cap - 1] = '\0';
	return sb->sb_buf;
}

int
naas_strbuf_space(struct naas_strbuf *sb)
{
	return sb->sb_cap > sb->sb_len ? sb->sb_cap - sb->sb_len : 0;
}

void
naas_strbuf_add(struct naas_strbuf *sb, const char *buf, int bufsz)
{
	int len, space;

	space = naas_strbuf_space(sb);
	len = NAAS_MIN(bufsz, space);
	memcpy(sb->sb_buf + sb->sb_len, buf, len);
	sb->sb_len += bufsz;
}

void
naas_strbuf_adds(struct naas_strbuf *sb, const char *s)
{
	naas_strbuf_add(sb, s, strlen(s));
}

void
naas_strbuf_vaddf(struct naas_strbuf *sb, const char *format, va_list ap)
{
	int space, len;

	space = naas_strbuf_space(sb);
	len = vsnprintf(sb->sb_buf + sb->sb_len, space, format, ap);
	sb->sb_len += len;
}

void
naas_strbuf_addf(struct naas_strbuf *sb, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	naas_strbuf_vaddf(sb, format, ap);
	va_end(ap);
}

void
naas_strbuf_add_inet(struct naas_strbuf *sb, int family, const void *src)
{
	const char *s;
	char inet_buf[INET6_ADDRSTRLEN];

	s = inet_ntop(family, src, inet_buf, sizeof(inet_buf));
	naas_strbuf_adds(sb, s);
}
