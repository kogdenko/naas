#ifndef NAAS_VPP_API_H
#define NAAS_VPP_API_H

#include <inttypes.h>
#include <netinet/in.h>

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vpp-api/client/vppapiclient.h>
#include <vnet/interface.api_types.h>
#include <vnet/ip/ip.api_enum.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/srv6/sr.api_enum.h>
#include <vnet/srv6/sr.api_types.h>
#include <vnet/ipsec/ipsec.api_types.h>
#include <vnet/ipip/ipip.api_types.h>
#include <vpp_plugins/linux_cp/lcp.api_types.h>

#define NAAS_API_INTERFACE_NAME_MAX 64

typedef void (*naas_api_lcp_itf_pair_get_f)(void *user,
		int phy_sw_if_index, int host_if_index);


int naas_api_init(const char *client_name);
void naas_api_deinit(void);

struct naas_api_sw_interface {
	uint32_t sw_if_index;
	char interface_name[NAAS_API_INTERFACE_NAME_MAX];
};
typedef void (*naas_api_sw_interface_dump_f)(void *user, struct naas_api_sw_interface *interface);
void naas_api_sw_interface_dump(naas_api_sw_interface_dump_f handler, void *user);

int naas_api_sw_interface_set_flags(uint32_t sw_if_index, vl_api_if_status_flags_t flags);

int naas_api_sw_interface_set_unnumbered(int is_add, uint32_t sw_if_index,
		uint32_t unnumbered_sw_if_index);

int naas_api_ip_route_add_del(int is_add, struct in_addr prefix, int prefixlen, int sw_if_index);

void naas_api_lcp_itf_pair_get(naas_api_lcp_itf_pair_get_f handler, void *user);

void naas_api_set_sr_encaps_source_addr(struct in6_addr *addr);

void naas_api_ip_table_add_del(int is_add, int is_ip6, int table_id);

void naas_api_sr_localsid_add_del(int is_add, int action, void *addr, int table_id);

void naas_api_sr_policy_add(uint8_t *bsid, struct in6_addr *segments, int first_segment);

void naas_api_sr_policy_del(uint8_t *bsid);

void naas_api_sr_steering_add_del(int is_add, int phy_sw_if_index, int family,
		void *prefix, int prefixlen, int table_id, const uint8_t *bsid);

int naas_api_ipsec_tunnel_protect_update(uint32_t sw_if_index, uint32_t sa_in, uint32_t sa_out);

typedef void (*naas_api_ipsec_sa_dump_f)(void *user, uint32_t sad_id, uint32_t spi);
void naas_api_ipsec_sa_dump(naas_api_ipsec_sa_dump_f handler, void *user);

struct naas_ipip_add_tunnel_ret {
	uint32_t sw_if_index;
};
int naas_ipip_add_tunnel(int instance, struct in_addr src, struct in_addr dst,
		struct naas_ipip_add_tunnel_ret *ret);

#endif // NAAS_VPP_API_H
