#ifndef NAAS_STRBUF_H
#define NAAS_STRBUF_H

#include <stdarg.h>

struct naas_strbuf {
	char *sb_buf;
	int sb_len;
	int sb_cap;
};

void naas_strbuf_init(struct naas_strbuf *sb, char *buf, int bufsz);
char *naas_strbuf_cstr(struct naas_strbuf *sb);
int naas_strbuf_space(struct naas_strbuf *sb);
void naas_strbuf_add(struct naas_strbuf *sb, const char *buf, int bufsz);
void naas_strbuf_adds(struct naas_strbuf *sb, const char *s);
void naas_strbuf_vaddf(struct naas_strbuf *sb, const char *format, va_list ap);
void naas_strbuf_addf(struct naas_strbuf *sb, const char *format, ...)
	__attribute__((format(printf, 2, 3)));
void naas_strbuf_add_inet(struct naas_strbuf *sb, int family, const void *src);

#endif // NAAS_STRBUF_H
