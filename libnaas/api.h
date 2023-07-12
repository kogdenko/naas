#ifndef NAAS_VPP_API_H
#define NAAS_VPP_API_H

#include <inttypes.h>
#include <netinet/in.h>

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vpp-api/client/vppapiclient.h>
#include <vpp/api/vpe.api_types.h>
#include <vnet/interface.api_types.h>
#include <vnet/ip/ip.api_enum.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/srv6/sr.api_enum.h>
#include <vnet/srv6/sr.api_types.h>
#include <vnet/ipsec/ipsec.api_types.h>
#include <vnet/ipip/ipip.api_types.h>
#include <vpp_plugins/linux_cp/lcp.api_types.h>

#include "utils.h"

#define NAAS_API_INTERFACE_NAME_MAX 64

int naas_api_init(const char *client_name);
void naas_api_deinit(void);

void naas_api_msg_free(void *data);

int naas_api_invoke(void *m, int mlen, void **r, int rlen);

#define NAAS_API_INVOKE3(mp, mlen, rp) \
({ \
	int rc; \
	i32 retval; \
	naas_err_t err; \
\
	rp = NULL; \
	rc = naas_api_invoke(mp, mlen, (void **)&rp, sizeof(*rp)); \
	if (rc < 0) { \
		err.num = -rc; \
		err.type = NAAS_ERR_ERRNO; \
	} else { \
		retval = ntohl(rp->retval); \
		if (retval > 0) { \
			err.type = NAAS_ERR_ERRNO; \
			err.num = EINVAL; \
		} else { \
			err.type = NAAS_ERR_VNET; \
			err.num = -retval; \
		} \
	} \
\
	err; \
})

#define NAAS_API_INVOKE(mp, rp) NAAS_API_INVOKE3(&mp, sizeof(mp), rp)

typedef int (naas_api_dump_handler_t)(void *user, void *user2, void *data, int len);
naas_err_t naas_api_dump(void *mp, int mlen, char *details_msg_name, naas_api_dump_handler_t handler,
		void *user0, void *user1);

naas_err_t naas_api_show_version();

struct naas_api_sw_interface {
	uint32_t sw_if_index;
	vl_api_if_status_flags_t flags;
	char interface_name[NAAS_API_INTERFACE_NAME_MAX];
};
typedef void (*naas_api_sw_interface_dump_f)(void *user, struct naas_api_sw_interface *interface);
naas_err_t naas_api_sw_interface_dump(naas_api_sw_interface_dump_f handler, void *user,
		const char *name_filter);

naas_err_t naas_api_create_loopback(uint32_t *p_sw_if_index);

naas_err_t naas_api_sw_interface_set_flags(uint32_t sw_if_index, vl_api_if_status_flags_t flags);

naas_err_t naas_api_sw_interface_set_unnumbered(int is_add, uint32_t sw_if_index,
		uint32_t unnumbered_sw_if_index);

naas_err_t naas_api_ip_route_add_del(int is_add, int table_id,
		struct in_addr prefix, int prefixlen, int sw_if_index);

typedef void (*naas_api_lcp_itf_pair_get_f)(void *user, int phy_sw_if_index, int host_if_index);
naas_err_t naas_api_lcp_itf_pair_get(naas_api_lcp_itf_pair_get_f handler, void *user);

naas_err_t naas_api_set_sr_encaps_source_addr(struct in6_addr *addr);

naas_err_t naas_api_ip_table_add_del(int is_add, int is_ip6, int table_id);

naas_err_t naas_api_sr_localsid_add_del(int is_add, int action, void *addr, int table_id);

naas_err_t naas_api_sr_policy_add(uint8_t *bsid, struct in6_addr *segments, int first_segment);

naas_err_t naas_api_sr_policy_del(uint8_t *bsid);

naas_err_t naas_api_sr_steering_add_del(int is_add, int phy_sw_if_index, int family,
		void *prefix, int prefixlen, int table_id, const uint8_t *bsid);

naas_err_t naas_api_ipsec_spd_add_del(int is_add, uint32_t spd_id);

naas_err_t naas_api_ipsec_itf_create(int instance, uint32_t *sw_if_index);

naas_err_t naas_api_ipsec_itf_delete(uint32_t sw_if_index);

naas_err_t naas_api_ipsec_spd_add_del(int is_add, uint32_t spd_id);

naas_err_t naas_api_ipsec_tunnel_protect_dump(uint32_t sw_if_index,
		uint32_t *sa_in, uint32_t *sa_out);

naas_err_t naas_api_ipsec_tunnel_protect_update(uint32_t sw_if_index,
		uint32_t sa_in, uint32_t sa_out);

typedef void (*naas_api_ipsec_sa_dump_f)(void *user, uint32_t sad_id, uint32_t spi);
naas_err_t naas_api_ipsec_sa_dump(naas_api_ipsec_sa_dump_f handler, void *user);

naas_err_t naas_api_ipip_add_tunnel(int instance, struct in_addr src, struct in_addr dst,
		uint32_t *sw_if_index);

#endif // NAAS_VPP_API_H
