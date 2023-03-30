#ifndef NAAS_COMMON_UTILS_H
#define NAAS_COMMON_UTILS_H

#include <inttypes.h>
#include <stddef.h>

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

void *naas_xmalloc(size_t size);
char *naas_strzcpy(char *, const char *, size_t);
const char *naas_inet6_ntop(const void *in6);
const char *naas_bool_str(int b);

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
