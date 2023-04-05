#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <naas-common/utils.h>
#include <naas-common/log.h>

#include "api.h"

typedef void (*naas_api_vac_f)(void *user, void *data, int len);

int g_naas_api_vac_reply_id;
void *g_naas_api_vac_user;
naas_api_vac_f g_naas_api_vac_fn;

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
naas_vac_callback(unsigned char *r, int rlen)
{
	g_naas_api_vac_reply_id = ntohs(*((uint16_t *)r));
	if (g_naas_api_vac_fn != NULL) {
		(*g_naas_api_vac_fn)(g_naas_api_vac_user, r, rlen);
	}
}

static void
naas_vac_write(int reply_id, void *m, int mlen, naas_api_vac_f fn, void *user)
{
	g_naas_api_vac_fn = fn;
	g_naas_api_vac_user = user;

	vac_write(m, mlen);

	while (g_naas_api_vac_reply_id != reply_id) {
		usleep(1000);
	}
	g_naas_api_vac_fn = NULL;
}

struct naas_vac_invoke_udata {
	int rlen;
	void *r;
};

static void
naas_vac_invoke_handler(void *user, void *r, int rlen)
{
	struct naas_vac_invoke_udata *udata;

	udata = user;
	if (udata->rlen != rlen) {
		udata->rlen = -1;
	} else {
		clib_memcpy(udata->r, r, rlen);
	}

}

static int
naas_vac_invoke(int reply_id, void *m, int mlen, void *r, int rlen)
{
	struct naas_vac_invoke_udata udata;

	udata.r = r;
	udata.rlen = rlen;

	naas_vac_write(reply_id, m, mlen, naas_vac_invoke_handler, &udata);

	return udata.rlen < 0 ? -EINVAL : 0;
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

void
naas_api_deinit(void)
{
	vac_disconnect();
	naas_logf(LOG_NOTICE, 0, "[VPP][API] Disconnected");
}

struct naas_api_sw_interface_details_udata {
	naas_api_sw_interface_dump_f handler;
	void *user;
};

static void
naas_api_sw_interface_details_handler(void *user, void *data, int len)
{
	vl_api_sw_interface_details_t *mp;
	struct naas_api_sw_interface_details_udata *udata;
	struct naas_api_sw_interface interface;

	if (len != sizeof(*mp)) {
		return;
	}
	mp = data;
	udata = user;

	interface.sw_if_index = ntohl(mp->sw_if_index);
	naas_strzcpy(interface.interface_name, (char *)mp->interface_name,
			sizeof(interface.interface_name));

	if (udata->handler != NULL) {
		udata->handler(udata->user, &interface);
	}

	naas_logf(LOG_NOTICE, 0,
"[VPP][API][sw_interface_dump] interfcae_name='%s', sw_if_index=%d",
			interface.interface_name, interface.sw_if_index);
}

void
naas_api_sw_interface_dump(naas_api_sw_interface_dump_f handler, void *user)
{
	int msg_id, reply_id;
	vl_api_sw_interface_dump_t mp;
	struct naas_api_sw_interface_details_udata udata;

	msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_DUMP_CRC);
	reply_id = vac_get_msg_index(VL_API_SW_INTERFACE_DETAILS_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);

	udata.user = user;
	udata.handler = handler;

	naas_vac_write(reply_id, &mp, sizeof(mp),
			naas_api_sw_interface_details_handler, &udata);
}

int
naas_api_sw_interface_set_flags(uint32_t sw_if_index, vl_api_if_status_flags_t flags)
{
	int rc, msg_id, reply_id;
	vl_api_sw_interface_set_flags_t mp;
	vl_api_sw_interface_set_flags_reply_t rp;

	msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_FLAGS_CRC);
	reply_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_FLAGS_REPLY_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.sw_if_index = htonl(sw_if_index);
	mp.flags = htonl(flags);

	rc = naas_vac_invoke(reply_id, &mp, sizeof(mp), &rp, sizeof(rp));
	if (rc == 0) {
		rc = ntohl(rp.retval);
	}

	naas_logf(LOG_NOTICE, 0,
"[VPP][API][sw_interface_set_flags] sw_if_index=%u, flags=%x, rc=%d",
			sw_if_index, flags, rc);

	return rc;
}

int
naas_api_sw_interface_set_unnumbered(int is_add, uint32_t sw_if_index,
		uint32_t unnumbered_sw_if_index)
{
	int rc, msg_id, reply_id;
	vl_api_sw_interface_set_unnumbered_t mp;
	vl_api_sw_interface_set_unnumbered_reply_t rp;

	msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_UNNUMBERED_CRC);
	reply_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_UNNUMBERED_REPLY_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.is_add = is_add;
	mp.sw_if_index = htonl(sw_if_index);
	mp.unnumbered_sw_if_index = htonl(unnumbered_sw_if_index);

	rc = naas_vac_invoke(reply_id, &mp, sizeof(mp), &rp, sizeof(rp));
	if (rc == 0) {
		rc = ntohl(rp.retval);
	}

	naas_logf(LOG_NOTICE, 0,
"[VPP][API][sw_interface_set_unnumbered] is_add=%d, sw_if_index=%u, unnumbered_sw_if_index=%u, rc=%d",
			is_add, sw_if_index, unnumbered_sw_if_index, rc);

	return rc;
}

typedef struct naas_api_vl_api_ip_route_add_del {
	vl_api_ip_route_add_del_t base;
	vl_api_fib_path_t path;
} naas_api_vl_api_ip_route_add_del_t;

int
naas_api_ip_route_add_del(int is_add, struct in_addr prefix, int prefixlen, int sw_if_index)
{
	int rc, msg_id, reply_id;
	naas_api_vl_api_ip_route_add_del_t mp;
	vl_api_ip_route_add_del_reply_t rp;

	msg_id = vac_get_msg_index(VL_API_IP_ROUTE_ADD_DEL_CRC);
	reply_id = vac_get_msg_index(VL_API_IP_ROUTE_ADD_DEL_REPLY_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp.base._vl_msg_id = ntohs(msg_id);
	mp.base.is_add = is_add;
	mp.base.route.prefix.len = prefixlen;
	mp.base.route.prefix.address.af = ADDRESS_IP4;
	clib_memcpy(mp.base.route.prefix.address.un.ip4, &prefix.s_addr, 4);
	mp.base.route.n_paths = 1;
	mp.path.sw_if_index = htonl(sw_if_index);

	rc = naas_vac_invoke(reply_id, &mp, sizeof(mp), &rp, sizeof(rp));
	if (rc == 0) {
		rc = ntohl(rp.retval);
	}

	naas_logf(LOG_NOTICE, 0,
"[VPP][API][ip_route_add_del] is_add=%d, prefix=%s/%u, sw_if_index=%u, rc=%d",
			is_add, inet_ntoa(prefix), prefixlen, sw_if_index, rc);

	return rc;

}

// vat2: lcp_itf_pair_get; cursor = 0
struct naas_api_lcp_itf_pair_details_udata {
	void *user;
	naas_api_lcp_itf_pair_get_f handler;
};

static void
naas_api_lcp_itf_pair_details_handler(void *user, void *data, int len)
{
	int rc;
	vl_api_lcp_itf_pair_details_t *mp;
	struct naas_api_lcp_itf_pair_details_udata *udata;

	if (len != sizeof(*mp)) {
		return;
	}
	mp = data;
	udata = user;

	rc = if_nametoindex((const char *)mp->host_if_name);
	if (rc == 0) {
		naas_logf(LOG_ERR, errno, "if_nametoindex('%s') failed", mp->host_if_name);
		return;
	}

	if (udata->handler != NULL) {
		udata->handler(udata->user, ntohl(mp->phy_sw_if_index), rc);
	}

	naas_logf(LOG_NOTICE, 0,
"[VPP][API][lcp_itf_pair_get] host_if_name='%s', linux_if_index=%d, vpp_if_index=%d",
			mp->host_if_name, rc, ntohl(mp->phy_sw_if_index));
}

void
naas_api_lcp_itf_pair_get(naas_api_lcp_itf_pair_get_f handler, void *user)
{
	int msg_id, reply_id;
	vl_api_lcp_itf_pair_get_t mp;
	api_main_t *am;
	struct naas_api_lcp_itf_pair_details_udata udata;

	am = vlibapi_get_main();

	msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_GET_CRC);
	reply_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_GET_REPLY_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.client_index = am->my_client_index;
	mp.cursor = htonl(0);

	udata.handler = handler;
	udata.user = user;

	naas_vac_write(reply_id, &mp, sizeof(mp),
			naas_api_lcp_itf_pair_details_handler, &udata);
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

	naas_vac_write(reply_id, &mp, sizeof(mp), NULL, NULL);

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

	naas_vac_write(reply_id, (void *)&mp, sizeof(mp), NULL, NULL);

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

	naas_vac_write(reply_id, &mp, sizeof(mp), NULL, NULL);

	naas_logf(LOG_INFO, 0,
"[VPP][API][sr_localsid_add_del] is_del=%s, localsid=%s, sw_if_index=%d, behavior=\"%s\"",
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
	
	naas_vac_write(reply_id, &mp, sizeof(mp), NULL, NULL);

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

	naas_vac_write(reply_id, &mp, sizeof(mp), NULL, NULL);

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

	naas_vac_write(reply_id, &mp, sizeof(mp), NULL, NULL);

	naas_logf(LOG_INFO, 0, "[VPP][API][sr_steering_%s] bsid=%s, table_id=%d\n",
			is_add ? "add" : "del", naas_inet6_ntop(bsid), table_id);
}

typedef struct naas_api_vl_api_ipsec_tunnel_protect_update {
	vl_api_ipsec_tunnel_protect_update_t base;
	uint32_t sa_in;
} naas_api_vl_api_ipsec_tunnel_protect_update_t;

int
naas_api_ipsec_tunnel_protect_update(uint32_t sw_if_index, uint32_t sa_in, uint32_t sa_out)
{
	int rc, msg_id, reply_id;
	naas_api_vl_api_ipsec_tunnel_protect_update_t mp;
	vl_api_ipsec_tunnel_protect_update_reply_t rp;

	msg_id = vac_get_msg_index(VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_CRC);
	reply_id = vac_get_msg_index(VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_REPLY_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp.base._vl_msg_id = ntohs(msg_id);
	mp.base.tunnel.sw_if_index = htonl(sw_if_index);
	mp.base.tunnel.sa_out = htonl(sa_out);
	mp.base.tunnel.n_sa_in = 1;
	mp.sa_in = htonl(sa_in);	

	rc = naas_vac_invoke(reply_id, &mp, sizeof(mp), &rp, sizeof(rp));
	if (rc == 0) {
		rc = ntohl(rp.retval);
	}

	naas_logf(LOG_NOTICE, 0, "[VPP][API][ipsec_tunnel_protect_update] sw_if_index=%u, sa_in=%u, sa_out=%u, rc=%d",
			sw_if_index, sa_in, sa_out, rc);

	return rc;
}

// VPP ctl:
// show ipsec sa
struct naas_api_ipsec_sa_details_udata {
	naas_api_ipsec_sa_dump_f handler;
	void *user;
};

static void
naas_api_ipsec_sa_details_handler(void *user, void *data, int len)
{
	uint32_t sad_id, spi;
	vl_api_ipsec_sa_details_t *mp;
	struct naas_api_ipsec_sa_details_udata *udata;

	if (len != sizeof(*mp)) {
		return;
	}
	mp = data;
	udata = user;

	sad_id = ntohl(mp->entry.sad_id);
	spi = ntohl(mp->entry.spi);
	udata->handler(udata->user, sad_id, spi);

	naas_logf(LOG_NOTICE, 0, "[VPP][API][ipsec_sa_dump] sad_id=%u, spi=%x", sad_id, spi);
}

void
naas_api_ipsec_sa_dump(naas_api_ipsec_sa_dump_f handler, void *user)
{
	int msg_id, reply_id;
	vl_api_ipsec_sa_dump_t mp;
	struct naas_api_ipsec_sa_details_udata udata;

	msg_id = vac_get_msg_index(VL_API_IPSEC_SA_DUMP_CRC);
	reply_id = vac_get_msg_index(VL_API_IPSEC_SA_DETAILS_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);

	udata.handler = handler;
	udata.user = user;

	naas_vac_write(reply_id, (void *)&mp, sizeof(mp),
			naas_api_ipsec_sa_details_handler, &udata);
}

int
naas_ipip_add_tunnel(int instance, struct in_addr src, struct in_addr dst,
		struct naas_ipip_add_tunnel_ret *ret)
{
	int rc, msg_id, reply_id;
	vl_api_ipip_add_tunnel_t mp;
	vl_api_ipip_add_tunnel_reply_t rp;


	msg_id = vac_get_msg_index(VL_API_IPIP_ADD_TUNNEL_CRC);
	reply_id = vac_get_msg_index(VL_API_IPIP_ADD_TUNNEL_REPLY_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.tunnel.instance = htonl(instance);
	mp.tunnel.src.af = ADDRESS_IP4;
	clib_memcpy(mp.tunnel.src.un.ip4, &src.s_addr, 4);
	mp.tunnel.dst.af = ADDRESS_IP4;
	clib_memcpy(mp.tunnel.dst.un.ip4, &dst.s_addr, 4);
	mp.tunnel.mode = TUNNEL_API_MODE_P2P;

	rc = naas_vac_invoke(reply_id, &mp, sizeof(mp), &rp, sizeof(rp));

	if (rc == 0) {
		rc = ntohl(rp.retval);
		ret->sw_if_index = ntohl(rp.sw_if_index);
	}

	naas_logf(LOG_NOTICE, 0, "[VPP][API][ipip_add_tunnel] instance=%u, sw_if_index=%u, rc=%d",
			instance, ret->sw_if_index, rc);

	return rc;
}
