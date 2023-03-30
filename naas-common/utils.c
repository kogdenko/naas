#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "utils.h"
#include "log.h"

void *
naas_xmalloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (ptr == NULL) {
		naas_logf(LOG_ERR, errno, "malloc(%zu) failed", size);
		abort();
	}
	return ptr;
}

char *
naas_strzcpy(char *dest, const char *src, size_t n)
{                                                                                          
	size_t i;
                                             
	for (i = 0; i < n - 1; ++i) {
		if (src[i] == '\0') {
			break;
		}
		dest[i] = src[i];
	}
	dest[i] = '\0';
	return dest;
}

const char *
naas_inet6_ntop(const void *in6)
{
	static char in6_buf[INET6_ADDRSTRLEN];

	return inet_ntop(AF_INET6, in6, in6_buf, sizeof(in6_buf));
}

const char *
naas_bool_str(int b)
{
	return b ? "true" : "false";
}
