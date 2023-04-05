#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
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

int
naas_inet_aton(const char *cp, struct in_addr *inp, unsigned int *maskp)
{
	char buf[INET_ADDRSTRLEN + 16];
	unsigned int mask;
	char *delim, *endptr;

	naas_strzcpy(buf, cp, sizeof(buf));

	delim = strchr(buf, '/');
	if (delim == NULL) {
		mask = 32;
	} else {
		*delim = '\0';
		mask = strtoul(delim + 1, &endptr, 10);
		if (*endptr != '\0' || mask > 32) {
			return -EINVAL;
		}
	}

	if (maskp != NULL) {
		*maskp = mask;
	}

	if (inet_aton(buf, inp) == 0) {
		return -errno;
	} else {
		return 0;
	}
}

const char *
naas_bool_str(int b)
{
	return b ? "true" : "false";
}

void
naas_print_invalidarg(const char *opt, const char *optarg)
{
	fprintf(stderr, "'%s': Invalid argument: '%s'\n", opt, optarg);
}


void
naas_print_unspecifiedarg(const char *opt)
{
	fprintf(stderr, "Unspecified argument: '%s'\n", opt);
}
