#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <naas-common/utils.h>
#include <naas-common/log.h>

#include "api.h"

int g_lcp_vac_callback_msg_id;
void (*g_lcp_vac_callback_fn)(void *data, int len);

static const char *
naas_api_sr_behavior_api_str(int behavior)
{
	switch (behavior) {
	case SR_BEHAVIOR_API_END: return "SR_BEHAVIOR_API_END";
	case SR_BEHAVIOR_API_X: return "SR_BEHAVIOR_API_X";
	case SR_BEHAVIOR_API_T: return "SR_BEHAVIOR_API_T";
	case SR_BEHAVIOR_API_DX2: return "SR_BEHAVIOR_API_DX2";
	case SR_BEHAVIOR_API_DX6: return "SR_BEHAVIOR_API_DX6";
	case SR_BEHAVIOR_API_DX4: return "SR_BEHAVIOR_API_DX4";
	case SR_BEHAVIOR_API_DT4: return "SR_BEHAVIOR_API_DT4";
	case SR_BEHAVIOR_API_DT6: return "SR_BEHAVIOR_API_DT6";
	default: return "\"Invalid ENUM\"";
	}
}

static void
naas_vac_callback(unsigned char *data, int len)
{
	g_lcp_vac_callback_msg_id = ntohs(*((uint16_t *)data));
	if (g_lcp_vac_callback_fn != NULL) {
		(*g_lcp_vac_callback_fn)(data, len);
	}
}

static void
naas_api_vac_wait(int msg_id)
{
	while (g_lcp_vac_callback_msg_id != msg_id) {
		usleep(1000);
	}
}

int
naas_api_init(const char *client_name)
{
	int rc;
	char client_name_buf[1024];

	clib_mem_init(0, 64 << 20); // 20 Mb

	naas_strzcpy(client_name_buf, client_name, sizeof(client_name_buf));
	rc = vac_connect(client_name_buf, NULL, naas_vac_callback, 32);
	if (rc != 0) {
		naas_logf(LOG_ERR, 0, "[VPP][API] Connection failed");
		return rc;
	}
	naas_logf(LOG_NOTICE, 0, "[VPP][API] Connected");
	return 0;

}

// vat2: lcp_itf_pair_get; cursor = 0
naas_api_lcp_itf_pair_get_handler_t g_naas_api_lcp_itf_pair_get_handler;
void *g_naas_api_lcp_itf_pair_get_user;

static void
naas_api_lcp_itf_pair_details_handler(void *data, int len)
{
	int rc;
	vl_api_lcp_itf_pair_details_t *mp;

	if (len != sizeof(*mp)) {
		return;
	}
	mp = data;

	rc = if_nametoindex((const char *)mp->host_if_name);
	if (rc == 0) {
		naas_logf(LOG_ERR, errno, "if_nametoindex('%s') failed", mp->host_if_name);
		return;
	}

	(*g_naas_api_lcp_itf_pair_get_handler)(g_naas_api_lcp_itf_pair_get_user,
			ntohl(mp->phy_sw_if_index), rc);

	naas_logf(LOG_NOTICE, 0, "[VPP][API][lcp_itf_pair_get] host_if_name='%s', linux_if_index=%d, vpp_if_index=%d",
			mp->host_if_name, rc, ntohl(mp->phy_sw_if_index));
}

void
naas_api_lcp_itf_pair_get(naas_api_lcp_itf_pair_get_handler_t handler, void *user)
{
	int msg_id, reply_id;
	vl_api_lcp_itf_pair_get_t mp;
	api_main_t *am;

	am = vlibapi_get_main();

	msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_GET_CRC);
	reply_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_GET_REPLY_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.client_index = am->my_client_index;
	mp.cursor = htonl(0);

	g_naas_api_lcp_itf_pair_get_handler = handler;
	g_naas_api_lcp_itf_pair_get_user = user;

	g_lcp_vac_callback_fn = naas_api_lcp_itf_pair_details_handler;
	vac_write((void *)&mp, sizeof(mp));

	naas_api_vac_wait(reply_id);
	g_lcp_vac_callback_fn = NULL;
}

// set sr encaps source addr 2001:db8::1
void
naas_api_set_sr_encaps_source_addr(struct in6_addr *addr)
{
	int msg_id, reply_id;
	vl_api_sr_set_encap_source_t mp;
	api_main_t *am;

	am = vlibapi_get_main();

	msg_id = vac_get_msg_index(VL_API_SR_SET_ENCAP_SOURCE_CRC);
	reply_id = vac_get_msg_index(VL_API_SR_SET_ENCAP_SOURCE_REPLY_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.client_index = am->my_client_index;
	clib_memcpy(mp.encaps_source, addr, 16);

	vac_write((void *)&mp, sizeof(mp));

	naas_api_vac_wait(reply_id);

	naas_logf(LOG_INFO, 0, "[VPP][API][set_sr_encaps_source_addr] tunsrc=%s",
			naas_inet6_ntop(addr));
}


// linux:	ip link add dev VRF13 type vrf table 13
// vppctl: 	ip table add 13
//		ip6 table add 13
// vat2: 	'ip_table_add_del' is_add=true, is_ip6=false, table_id=13
void
naas_api_ip_table_add_del(int is_add, int is_ip6, int table_id)
{
	int msg_id, reply_id;
	vl_api_ip_table_add_del_t mp;
	api_main_t *am;

	am = vlibapi_get_main();

	msg_id = vac_get_msg_index(VL_API_IP_TABLE_ADD_DEL_CRC);
	reply_id = vac_get_msg_index(VL_API_IP_TABLE_ADD_DEL_REPLY_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.client_index = am->my_client_index;
	mp.table.table_id = ntohl(table_id);
	mp.table.is_ip6 = is_ip6;
	mp.is_add = is_add;

	vac_write((void *)&mp, sizeof(mp));

	naas_api_vac_wait(reply_id);

	naas_logf(LOG_INFO, 0, "[VPP][API][ip_table_add_del] is_add=%s, is_ip6=%s, table_id=%d",
			naas_bool_str(is_ip6), naas_bool_str(is_add), table_id);
}

// Linux:
// ip -6 route add 2000:aaa8:0:0:100::/128 encap seg6local action End.DT6 table 13 dev VRF13
// ip -6 route add 2000:aaa8:0:0:100::/128 encap seg6local action End.DT4 vrftable 13  dev VRF13 
// 
// VPP ctl:
// sr localsid address 2000:aaa8:0:0:100:: behavior end.dt6 13
//
// VPP api:
// 'sr_localsid_add_del' is_del=false, localsid=2000:aaa8:0:0:100::, behavior=SR_BEHAVIOR_API_DT6

void
naas_api_sr_localsid_add_del(int is_add, int behavior, void *addr, int table_id)
{
	int msg_id, reply_id;
	vl_api_sr_localsid_add_del_t mp;
	api_main_t *am;

	am = vlibapi_get_main();

	msg_id = vac_get_msg_index(VL_API_SR_LOCALSID_ADD_DEL_CRC);
	reply_id = vac_get_msg_index(VL_API_SR_LOCALSID_ADD_DEL_REPLY_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.client_index = am->my_client_index;
	mp.is_del = !is_add;
	clib_memcpy(mp.localsid, addr, sizeof(mp.localsid));
	mp.sw_if_index = htonl(table_id);	
	mp.behavior = behavior;

	vac_write((void *)&mp, sizeof(mp));

	naas_api_vac_wait(reply_id);

	naas_logf(LOG_INFO, 0, "[VPP][API][sr_localsid_add_del] is_del=%s, localsid=%s, sw_if_index=%d, behavior=\"%s\"",
			naas_bool_str(mp.is_del), naas_inet6_ntop(mp.localsid), ntohl(mp.sw_if_index),
			naas_api_sr_behavior_api_str(mp.behavior));
}

// VPP ctl:
// sr policy add bsid 2000:aaa2:0:0:101:: next 2000:aaa2:0:0:100:: encap
void
naas_api_sr_policy_add(uint8_t *bsid, struct in6_addr *segments, int first_segment)
{
	int i, msg_id, reply_id;
	vl_api_sr_policy_add_t mp;
	api_main_t *am;

	if (first_segment >= NAAS_ARRAY_SIZE(mp.sids.sids)) {
		naas_logf(LOG_ERR, 0, "[VPP][API][sr_policy_add] failed (sids limit exceeded)");
		return;
	}

	am = vlibapi_get_main();

	msg_id = vac_get_msg_index(VL_API_SR_POLICY_ADD_CRC);
	reply_id = vac_get_msg_index(VL_API_SR_POLICY_ADD_REPLY_CRC);	

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.client_index = am->my_client_index;
	clib_memcpy(mp.bsid_addr, bsid, 16);
	mp.is_encap = true;
	mp.sids.num_sids = first_segment + 1;
	for (i = 0; i < mp.sids.num_sids; ++i) {
		clib_memcpy(mp.sids.sids[i], segments[i].s6_addr, 16);
	}
	
	vac_write((void *)&mp, sizeof(mp));

	naas_api_vac_wait(reply_id);

	naas_logf(LOG_INFO, 0, "[VPP][API][sr_policy_add] bsid=%s", naas_inet6_ntop(bsid));
}

void
naas_api_sr_policy_del(uint8_t *bsid)
{
	int msg_id, reply_id;
	vl_api_sr_policy_del_t mp;
	api_main_t *am;

	am = vlibapi_get_main();

	msg_id = vac_get_msg_index(VL_API_SR_POLICY_DEL_CRC);
	reply_id = vac_get_msg_index(VL_API_SR_POLICY_DEL_REPLY_CRC);	

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.client_index = am->my_client_index;
	clib_memcpy(mp.bsid_addr, bsid, 16);

	vac_write((void *)&mp, sizeof(mp));

	naas_api_vac_wait(reply_id);

	naas_logf(LOG_INFO, 0, "[VPP][API][sr_policy_del] bsid=%s", naas_inet6_ntop(bsid));
}

// Linux:
// ip r a 10.8.8.0/24 via inet6 fe80::5200:ff:fe03:3766 encap seg6 mode encap segs 2000:aaa2:0:0:100:: dev eth2 table 13
//
// VPP ctl:
// sr steer l3 10.8.8.0/24 via bsid 2000:aaa2:0:0:101:: fib-table 13
// show sr steering-policies
void
naas_api_sr_steering_add_del(int is_add, int phy_sw_if_index,
		int family, void *prefix, int prefixlen, int table_id, const uint8_t *bsid)
{
	int msg_id, reply_id;
	vl_api_sr_steering_add_del_t mp;
	api_main_t *am;

	am = vlibapi_get_main();

	msg_id = vac_get_msg_index(VL_API_SR_STEERING_ADD_DEL_CRC);
	reply_id = vac_get_msg_index(VL_API_SR_STEERING_ADD_DEL_REPLY_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.client_index = am->my_client_index;
	mp.is_del = !is_add;
	mp.table_id = htonl(table_id);
	clib_memcpy(mp.bsid_addr, bsid, 16);
	mp.prefix.len = prefixlen;
	mp.prefix.address.af = family;
	mp.sw_if_index = phy_sw_if_index;
	if (family == AF_INET) {
		mp.traffic_type = SR_STEER_API_IPV4;
		mp.prefix.address.af = ADDRESS_IP4;
		clib_memcpy(mp.prefix.address.un.ip4, prefix, 4);
	} else {
		mp.traffic_type = SR_STEER_API_IPV6;
		mp.prefix.address.af = ADDRESS_IP6;
		clib_memcpy(mp.prefix.address.un.ip6, prefix, 16);
	}

	vac_write((void *)&mp, sizeof(mp));

	naas_api_vac_wait(reply_id);

	naas_logf(LOG_INFO, 0, "[VPP][API][sr_steering_%s] bsid=%s, table_id=%d\n",
			is_add ? "add" : "del", naas_inet6_ntop(bsid), table_id);
}
