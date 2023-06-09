#ifndef NAAS_COMMON_UTILS_H
#define NAAS_COMMON_UTILS_H

#include <inttypes.h>
#include <stddef.h>
#include <arpa/inet.h>

#define NAAS_ERR_ERRNO (0) // errno by default
#define NAAS_ERR_VNET 1

#define naas_barrier() __asm__ __volatile__("": : :"memory")

#define naas_field_off(type, field) ((intptr_t)&((type *)0)->field)

#define naas_container_of(ptr, type, field) \
	((type *)((intptr_t)(ptr) - naas_field_off(type, field)))

#define NAAS_READ_ONCE(x) \
({ \
	union { \
		typeof(x) val; \
		uint8_t data[1]; \
	} u; \
	naas_read_once(&(x), u.data, sizeof(x)); \
	u.val; \
})

#define NAAS_WRITE_ONCE(x, v) \
({ \
	union { \
		typeof(x) val; \
		uint8_t data[1]; \
	} u = { \
		.val = (typeof(x))(v) \
	}; \
	naas_write_once(&(x), u.data, sizeof(x)); \
	u.val; \
})

#define naas_rcu_assign_pointer(p, v) \
({ \
	naas_barrier(); \
	NAAS_WRITE_ONCE(p, v); \
})

#define NAAS_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define NAAS_MIN(a, b) ((a) < (b) ? (a) : (b))

#define NAAS_INET_NTOA(src, dst) inet_ntop(AF_INET, src, dst, INET_ADDRSTRLEN)

typedef uint32_t be32_t;

typedef struct naas_err {
	uint16_t type;
	uint16_t num;
} naas_err_t;

void *naas_xmalloc(size_t size);
char *naas_strzcpy(char *, const char *, size_t);
const char *naas_inet_ntop(int af, const void *in6, char *addrstr);
#define naas_inet4_ntop(in4, addrstr) naas_inet_ntop(AF_INET, in4, addrstr)
#define naas_inet6_ntop(in6, addrstr) naas_inet_ntop(AF_INET6, in6, addrstr)
int naas_inet_aton(const char *cp, struct in_addr *inp, unsigned int *maskp);
const char *naas_bool_str(int b);
void naas_print_invalidarg(const char *opt, const char *optarg);
void naas_print_unspecifiedarg(const char *opt);

static inline void
naas_read_once(const volatile void *p, void *data, int size)
{
	switch (size) {
	case 1: *(uint8_t *)data = *(volatile uint8_t *)p; break;
	case 2: *(uint16_t *)data = *(volatile uint16_t *)p; break;
	case 4: *(uint32_t *)data = *(volatile uint32_t *)p; break;
	case 8: *(uint64_t *)data = *(volatile uint64_t *)p; break;
	}
}

static inline void
naas_write_once(volatile void *p, void *data, int size)
{
	switch (size) {
	case 1: *(volatile uint8_t *)p = *(uint8_t *)data; break;
	case 2: *(volatile uint16_t *)p = *(uint16_t *)data; break;
	case 4: *(volatile uint32_t *)p = *(uint32_t *)data; break;
	case 8: *(volatile uint64_t *)p = *(uint64_t *)data; break;
	}
}

#endif // NAAS_COMMON_UTILS_H
