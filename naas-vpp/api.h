#ifndef NAAS_VPP_API_H
#define NAAS_VPP_API_H

#include <netinet/in.h>

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vpp-api/client/vppapiclient.h>
#include <vnet/ip/ip.api_enum.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/srv6/sr.api_enum.h>
#include <vnet/srv6/sr.api_types.h>
#include <vpp_plugins/linux_cp/lcp.api_types.h>

typedef void (*naas_api_lcp_itf_pair_get_handler_t)(void *user,
		int phy_sw_if_index, int host_if_index);

int naas_api_init(const char *client_name);
void naas_api_lcp_itf_pair_get(naas_api_lcp_itf_pair_get_handler_t handler, void *user);
void naas_api_set_sr_encaps_source_addr(struct in6_addr *addr);
void naas_api_ip_table_add_del(int is_add, int is_ip6, int table_id);
void naas_api_sr_localsid_add_del(int is_add, int action, void *addr, int table_id);
void naas_api_sr_policy_add(uint8_t *bsid, struct in6_addr *segments, int first_segment);
void naas_api_sr_policy_del(uint8_t *bsid);
void naas_api_sr_steering_add_del(int is_add, int phy_sw_if_index, 
	int family, void *prefix, int prefixlen, int table_id, const uint8_t *bsid);

#endif // NAAS_VPP_API_H
