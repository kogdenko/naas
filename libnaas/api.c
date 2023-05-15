#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "utils.h"
#include "log.h"
#include "api.h"

#define vl_endianfun
#include <vlibmemory/memclnt.api.h>
#undef vl_endianfun

//typedef void (*naas_api_vac_f)(void *user, void *data, int len);

//static int g_naas_api_vac_reply_id;
//static void *g_naas_api_vac_user;
//static naas_api_vac_f g_naas_api_vac_fn;


static void
vl_api_address_create(vl_api_address_t *address, int af, void *in)
{
	if (af == AF_INET) {
		address->af = ADDRESS_IP4;
		clib_memcpy(address->un.ip4, in, 4);
	} else {
		address->af = ADDRESS_IP6;
		clib_memcpy(address->un.ip6, in, 16);
	}
}

int
vl_api_address_2_in(vl_api_address_t *address, void *in)
{
	if (address->af == ADDRESS_IP4) {
		clib_memcpy(in, address->un.ip4, 4);
		return AF_INET;
	} else {
		clib_memcpy(in, address->un.ip6, 16);
		return AF_INET6;
	}
}

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

static int
naas_vac_reconnect(const char *client_name)
{
	int rc;
	char client_name_buf[1024];

	naas_strzcpy(client_name_buf, client_name, sizeof(client_name_buf));
	rc = vac_connect(client_name_buf, NULL, NULL, 1024);
	if (rc != 0) {
		naas_logf(LOG_ERR, 0, "[VPP][API] Connection failed");
		return rc;
	}
	naas_logf(LOG_NOTICE, 0, "[VPP][API] Connected");
	return 0;
}

static int
naas_vac_read(char **data, int timeout)
{
	int rc, len;

	rc = vac_read(data, &len, timeout);
	switch (rc) {
	case 0:
		break;
	case VAC_NOT_CONNECTED:
		return -ECONNREFUSED;
	case VAC_TIMEOUT:
		return -ETIMEDOUT;
	default:
		return -EINTR;
	}

	assert(*data != NULL);
	assert(len != 0);

	return len;
}

static int
naas_vac_write(void *data, int len)
{
	int rc;

	rc = vac_write(data, len);
	if (rc >= 0) {
		return 0;
	}
	switch (rc) {
	case VAC_NOT_CONNECTED:
		return -ECONNREFUSED;
	default:
		return -EINTR;
	}
}

int
naas_api_init(const char *client_name)
{
	int rc;

	clib_mem_init(0, 64 << 20); // 20 Mb
	rc = naas_vac_reconnect(client_name);
	return rc;
}

void
naas_api_deinit(void)
{
	vac_disconnect();
	naas_logf(LOG_NOTICE, 0, "[VPP][API] Disconnected");
}

void
naas_api_msg_free(void *data)
{
	if (data != NULL) {
		vl_msg_api_free(data);
	}
}

static uint16_t
naas_api_ping(u32 context)
{
	int rc;
	vl_api_control_ping_t mp;

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_CRC);
	mp.context = context;
	vl_api_control_ping_t_endian(&mp);
	rc = naas_vac_write((void *)&mp, sizeof(mp));
	if (rc < 0) {
		return rc;
	}
  	return vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
}

int
naas_api_invoke(void *m, int mlen, void **r, int rlen)
{
	int rc, len;
	char *data;

	rc = naas_vac_write(m, mlen);
	if (rc < 0) {
		return rc;
	}

	rc = naas_vac_read(&data, 5);
	if (rc < 0) {
		return rc;
	}
	len = rc;

	if (len < rlen) {
		naas_api_msg_free(data);
		return -EINVAL;
	}

	*r = data;
	return 0;
}

int
naas_api_dump(void *mp, int mlen, char *details_msg_name, naas_api_dump_handler_t handler,
		void *user0, void *user1)
{
	int rc, rlen, details_msg_id, pong_msg_id, data_msg_id;
	char *data;

	details_msg_id = vac_get_msg_index(details_msg_name); 

	rc = naas_vac_write(mp, mlen);
	if (rc < 0) {
		return rc;
	}

	do {
		rc = naas_api_ping(123);
	} while (rc < 0);

	pong_msg_id = rc;

	do {
		rc = naas_vac_read(&data, 5);
		if (rc < 0) {
			return rc;
		}
		rlen = rc;
		rc = 0;

		data_msg_id = ntohs(*((u16 *)data));

		if (data_msg_id == pong_msg_id) {
			;
		} else if (data_msg_id == details_msg_id) {
			rc = (handler)(user0, user1, data, rlen);
		} else {
			naas_logf(LOG_ERR, 0, "%s: Unexpected message: %d",
					details_msg_name, data_msg_id);
		}

		naas_api_msg_free(data);

	} while (data_msg_id != pong_msg_id && rc == 0);

	return rc;
}

naas_err_t
naas_api_show_version(vl_api_show_version_reply_t *ver)
{
	int msg_id;
	naas_err_t err;
	vl_api_show_version_t mp;
	vl_api_show_version_reply_t *rp;
	
	msg_id = vac_get_msg_index(VL_API_SHOW_VERSION_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);

	err = NAAS_API_INVOKE(mp, rp);
	if (err.type == NAAS_ERR_VNET) {
		memcpy(ver, rp, sizeof(*ver));
	} else {
		clib_memset(ver, 0, sizeof(ver));
	}
	naas_api_msg_free(rp);

	naas_err_logf(LOG_INFO, err,
"[VPP][API][show_version] program=%s, version=%s, build_date=%s, build_directory=%s",
		ver->program, ver->version, ver->build_date, ver->build_directory);

	return err;

}

static int
naas_api_sw_interface_details(void *user0, void *user, void *data, int len)
{
	vl_api_sw_interface_details_t *details;
	naas_api_sw_interface_dump_f handler;
	struct naas_api_sw_interface interface;

	handler = user0;

	if (len != sizeof(*details)) {
		return -EINVAL;
	}
	details = data;

	interface.sw_if_index = ntohl(details->sw_if_index);
	interface.flags = details->flags;
	naas_strzcpy(interface.interface_name, (char *)details->interface_name,
			sizeof(interface.interface_name));

	if (handler != NULL) {
		(*handler)(user, &interface);
	}

	naas_logf(LOG_DEBUG,
"[VPP][API][sw_interface_dump] interfcae_name='%s', sw_if_index=%d",
			interface.interface_name, interface.sw_if_index);

	return 0;
}

typedef struct naas_api_vl_api_sw_interface_dump {
	vl_api_sw_interface_dump_t base;
	char name_filter[NAAS_API_INTERFACE_NAME_MAX];
} naas_api_vl_api_sw_interface_dump_t;

naas_err_t
naas_api_sw_interface_dump(naas_api_sw_interface_dump_f handler, void *user,
		const char *name_filter)
{
	int rc, name_filter_len, msg_id;
	naas_err_t err;
	naas_api_vl_api_sw_interface_dump_t mp;

	msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_DUMP_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp.base._vl_msg_id = ntohs(msg_id);

	if (name_filter == NULL) {
		name_filter_len = 0;
	} else {
		mp.base.name_filter_valid = true;
		name_filter_len = NAAS_MIN(strlen(name_filter), sizeof(mp.name_filter));
	}

  	mp.base.name_filter.length = htonl(name_filter_len);
	memcpy(mp.name_filter, name_filter, name_filter_len);

	rc = naas_api_dump(&mp, sizeof(mp), VL_API_SW_INTERFACE_DETAILS_CRC,
			naas_api_sw_interface_details, handler, user);

	err.num = -rc;
	err.type = NAAS_ERR_ERRNO;

	return err;
}

naas_err_t
naas_api_create_loopback(uint32_t *p_sw_if_index)
{
	int msg_id;
	uint32_t sw_if_index;
	naas_err_t err;
	vl_api_create_loopback_t mp;
	vl_api_create_loopback_reply_t *rp;
	
	msg_id = vac_get_msg_index(VL_API_CREATE_LOOPBACK_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);

	sw_if_index = ~0;

	err = NAAS_API_INVOKE(mp, rp);
	if (err.type == NAAS_ERR_VNET) {
		sw_if_index = ntohl(rp->sw_if_index);
	}
	naas_api_msg_free(rp);

	*p_sw_if_index = sw_if_index;

	naas_err_logf(LOG_INFO, err, "[VPP][API][create_loopback] sw_if_index=%u", sw_if_index);

	return err;
}

naas_err_t
naas_api_sw_interface_set_flags(uint32_t sw_if_index, vl_api_if_status_flags_t flags)
{
	int msg_id;
	naas_err_t err;
	vl_api_sw_interface_set_flags_t mp;
	vl_api_sw_interface_set_flags_reply_t *rp;

	msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_FLAGS_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.sw_if_index = htonl(sw_if_index);
	mp.flags = htonl(flags);

	err = NAAS_API_INVOKE(mp, rp);
	naas_api_msg_free(rp);

	naas_err_logf(LOG_INFO, err, "[VPP][API][sw_interface_set_flags] sw_if_index=%u, flags=%x",
			sw_if_index, flags);

	return err;
}

naas_err_t
naas_api_sw_interface_set_unnumbered(int is_add, uint32_t sw_if_index,
		uint32_t unnumbered_sw_if_index)
{
	int msg_id;
	naas_err_t err;
	vl_api_sw_interface_set_unnumbered_t mp;
	vl_api_sw_interface_set_unnumbered_reply_t *rp;

	msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_UNNUMBERED_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.is_add = is_add;
	mp.sw_if_index = htonl(sw_if_index);
	mp.unnumbered_sw_if_index = htonl(unnumbered_sw_if_index);

	err = NAAS_API_INVOKE(mp, rp);
	naas_api_msg_free(rp);

	naas_err_logf(LOG_INFO, err,
"[VPP][API][sw_interface_set_unnumbered] is_add=%d, sw_if_index=%u, unnumbered_sw_if_index=%u",
			is_add, sw_if_index, unnumbered_sw_if_index);

	return err;
}

typedef struct naas_api_vl_api_ip_route_add_del {
	vl_api_ip_route_add_del_t base;
	vl_api_fib_path_t path;
} naas_api_vl_api_ip_route_add_del_t;

naas_err_t
naas_api_ip_route_add_del(int is_add, struct in_addr prefix, int prefixlen, int sw_if_index)
{
	int msg_id;
	naas_err_t err;
	naas_api_vl_api_ip_route_add_del_t mp;
	vl_api_ip_route_add_del_reply_t *rp;

	msg_id = vac_get_msg_index(VL_API_IP_ROUTE_ADD_DEL_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp.base._vl_msg_id = ntohs(msg_id);
	mp.base.is_add = is_add;
	mp.base.route.prefix.len = prefixlen;
	vl_api_address_create(&mp.base.route.prefix.address, AF_INET, &prefix);
	mp.base.route.n_paths = 1;
	mp.path.sw_if_index = htonl(sw_if_index);

	err = NAAS_API_INVOKE(mp, rp);
	naas_api_msg_free(rp);

	naas_err_logf(LOG_INFO, err,
"[VPP][API][ip_route_add_del] is_add=%d, prefix=%s/%u, sw_if_index=%u",
			is_add, inet_ntoa(prefix), prefixlen, sw_if_index);

	return err;
}

// vat2: lcp_itf_pair_get; cursor = 0
static int
naas_api_lcp_itf_pair_details(naas_api_lcp_itf_pair_get_f handler, void *user, char *data, int len)
{
	int rc;
	uint32_t phy_sw_if_index;
	vl_api_lcp_itf_pair_details_t *details;

	if (len != sizeof(*details)) {
		return -EINVAL;
	}
	details = (void *)data;

	rc = if_nametoindex((const char *)details->host_if_name);
	if (rc == 0) {
		naas_errno_logf(LOG_ERR, errno, "if_nametoindex('%s') failed",
				details->host_if_name);
		return 0;
	}

	phy_sw_if_index = ntohl(details->phy_sw_if_index);
	if (handler != NULL) {
		(*handler)(user, phy_sw_if_index, rc);
	}

	naas_logf(LOG_INFO,
"[VPP][API][lcp_itf_pair_get] host_if_name='%s', linux_if_index=%d, vpp_if_index=%d",
			details->host_if_name, rc, phy_sw_if_index);

	return 0;
}

naas_err_t
naas_api_lcp_itf_pair_get(naas_api_lcp_itf_pair_get_f handler, void *user)
{
	int rc, len, msg_id, reply_msg_id, details_msg_id, data_msg_id;
	char *data;
	naas_err_t err;
	vl_api_lcp_itf_pair_get_t mp;
	vl_api_lcp_itf_pair_get_reply_t *reply;

	msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_GET_CRC);
	reply_msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_GET_REPLY_CRC);
	details_msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_DETAILS_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.cursor = htonl(0);

	rc = naas_vac_write((void *)&mp, sizeof(mp));
	if (rc < 0) {
		goto out;
	}

	do {
		rc = naas_vac_read(&data, 5);
		if (rc < 0) {
			break;
		}
		len = rc;

		data_msg_id = ntohs(*((u16 *)data));
		if (data_msg_id == reply_msg_id) {
			if (len != sizeof(*reply)) {
				rc = -EINVAL;
			} else {
				reply = (void *)data;
				rc = ntohl(reply->retval);
			}
		} else if (data_msg_id == details_msg_id) {
			rc = naas_api_lcp_itf_pair_details(handler, user, data, len);
		} else {
			rc = -EBADMSG;
		}

		naas_api_msg_free(data);
	} while (data_msg_id != reply_msg_id && rc == 0);

out:
	err.type = NAAS_ERR_ERRNO;
	err.num = -rc;
	return err;
}

// set sr encaps source addr 2001:db8::1
naas_err_t
naas_api_set_sr_encaps_source_addr(struct in6_addr *addr)
{
	int msg_id;
	naas_err_t err;
	char addrstr[INET6_ADDRSTRLEN];
	vl_api_sr_set_encap_source_t mp;
	vl_api_sr_set_encap_source_reply_t *rp;

	msg_id = vac_get_msg_index(VL_API_SR_SET_ENCAP_SOURCE_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	clib_memcpy(mp.encaps_source, addr, 16);

	err = NAAS_API_INVOKE(mp, rp);
	naas_api_msg_free(rp);

	naas_err_logf(LOG_INFO, err, "[VPP][API][set_sr_encaps_source_addr] tunsrc=%s",
			naas_inet6_ntop(addr, addrstr));

	return err;
}

// linux:	ip link add dev VRF13 type vrf table 13
// vppctl: 	ip table add 13
//		ip6 table add 13
// vat2: 	'ip_table_add_del' is_add=true, is_ip6=false, table_id=13
naas_err_t
naas_api_ip_table_add_del(int is_add, int is_ip6, int table_id)
{
	int msg_id;
	naas_err_t err;
	vl_api_ip_table_add_del_t mp;
	vl_api_ip_table_add_del_reply_t *rp;

	msg_id = vac_get_msg_index(VL_API_IP_TABLE_ADD_DEL_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.table.table_id = ntohl(table_id);
	mp.table.is_ip6 = is_ip6;
	mp.is_add = is_add;

	err = NAAS_API_INVOKE(mp, rp);
	naas_api_msg_free(rp);

	naas_err_logf(LOG_INFO, err, "[VPP][API][ip_table_add_del] is_add=%s, is_ip6=%s, table_id=%d",
			naas_bool_str(is_ip6), naas_bool_str(is_add), table_id);

	return err;
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

naas_err_t
naas_api_sr_localsid_add_del(int is_add, int behavior, void *addr, int table_id)
{
	int msg_id;
	naas_err_t err;
	char localsid_addrstr[INET6_ADDRSTRLEN];
	vl_api_sr_localsid_add_del_t mp;
	vl_api_sr_localsid_add_del_reply_t *rp;

	msg_id = vac_get_msg_index(VL_API_SR_LOCALSID_ADD_DEL_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.is_del = !is_add;
	clib_memcpy(mp.localsid, addr, sizeof(mp.localsid));
	mp.sw_if_index = htonl(table_id);	
	mp.behavior = behavior;

	err = NAAS_API_INVOKE(mp, rp);
	naas_api_msg_free(rp);

	naas_err_logf(LOG_INFO, err,
"[VPP][API][sr_localsid_add_del] is_del=%s, localsid=%s, sw_if_index=%d, behavior=\"%s\"",
			naas_bool_str(mp.is_del), naas_inet6_ntop(mp.localsid, localsid_addrstr),
			ntohl(mp.sw_if_index), naas_api_sr_behavior_api_str(mp.behavior));

	return err;
}

// VPP ctl:
// sr policy add bsid 2000:aaa2:0:0:101:: next 2000:aaa2:0:0:100:: encap
naas_err_t
naas_api_sr_policy_add(uint8_t *bsid, struct in6_addr *segments, int first_segment)
{
	int i, msg_id;
	char bsid_addrstr[INET6_ADDRSTRLEN];
	naas_err_t err;
	vl_api_sr_policy_add_t mp;
	vl_api_sr_policy_add_reply_t *rp;

	if (first_segment >= NAAS_ARRAY_SIZE(mp.sids.sids)) {
		naas_logf(LOG_ERR, 0, "[VPP][API][sr_policy_add] failed (sids limit exceeded)");
		err.type = NAAS_ERR_ERRNO;
		err.num = EINVAL;
		return err;
	}

	msg_id = vac_get_msg_index(VL_API_SR_POLICY_ADD_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	clib_memcpy(mp.bsid_addr, bsid, 16);
	mp.is_encap = true;
	mp.sids.num_sids = first_segment + 1;
	for (i = 0; i < mp.sids.num_sids; ++i) {
		clib_memcpy(mp.sids.sids[i], segments[i].s6_addr, 16);
	}
	
	err = NAAS_API_INVOKE(mp, rp);
	naas_api_msg_free(rp);

	naas_err_logf(LOG_INFO, err, "[VPP][API][sr_policy_add] bsid=%s",
			naas_inet6_ntop(bsid, bsid_addrstr));

	return err;
}

naas_err_t
naas_api_sr_policy_del(uint8_t *bsid)
{
	int msg_id;
	char bsid_addrstr[INET6_ADDRSTRLEN];
	naas_err_t err;
	vl_api_sr_policy_del_t mp;
	vl_api_sr_policy_del_reply_t *rp;

	msg_id = vac_get_msg_index(VL_API_SR_POLICY_DEL_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	clib_memcpy(mp.bsid_addr, bsid, 16);

	err = NAAS_API_INVOKE(mp, rp);
	naas_api_msg_free(rp);

	naas_err_logf(LOG_INFO, err, "[VPP][API][sr_policy_del] bsid=%s",
			naas_inet6_ntop(bsid, bsid_addrstr));

	return err;
}

// Linux:
// ip r a 10.8.8.0/24 via inet6 fe80::5200:ff:fe03:3766 encap seg6 mode encap segs 2000:aaa2:0:0:100:: dev eth2 table 13
//
// VPP ctl:
// sr steer l3 10.8.8.0/24 via bsid 2000:aaa2:0:0:101:: fib-table 13
// show sr steering-policies
naas_err_t
naas_api_sr_steering_add_del(int is_add, int phy_sw_if_index,
		int family, void *prefix, int prefixlen, int table_id, const uint8_t *bsid)
{
	int msg_id;
	char bsid_addrstr[INET6_ADDRSTRLEN];
	naas_err_t err;
	vl_api_sr_steering_add_del_t mp;
	vl_api_sr_steering_add_del_reply_t *rp;

	msg_id = vac_get_msg_index(VL_API_SR_STEERING_ADD_DEL_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.is_del = !is_add;
	mp.table_id = htonl(table_id);
	clib_memcpy(mp.bsid_addr, bsid, 16);
	mp.prefix.len = prefixlen;
	mp.sw_if_index = phy_sw_if_index;
	vl_api_address_create(&mp.prefix.address, family, prefix);
	if (family == AF_INET) {
		mp.traffic_type = SR_STEER_API_IPV4;
	} else {
		mp.traffic_type = SR_STEER_API_IPV6;
	}

	err = NAAS_API_INVOKE(mp, rp);
	naas_api_msg_free(rp);

	naas_err_logf(LOG_INFO, err, "[VPP][API][sr_steering_%s] bsid=%s, table_id=%d",
			is_add ? "add" : "del", naas_inet6_ntop(bsid, bsid_addrstr), table_id);

	return err;
}

naas_err_t
naas_api_ipsec_spd_add_del(int is_add, uint32_t spd_id)
{
	int msg_id;
	naas_err_t err;
	vl_api_ipsec_spd_add_del_t mp;
	vl_api_ipsec_spd_add_del_reply_t *rp;

	msg_id = vac_get_msg_index(VL_API_IPSEC_SPD_ADD_DEL_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.is_add = is_add;
	mp.spd_id = htonl(spd_id);

	err = NAAS_API_INVOKE(mp, rp);
	naas_api_msg_free(rp);

	naas_err_logf(LOG_INFO, err, "[VPP][API][ipsec_spd_%s] spd_id=%u",
			is_add ? "add" : "del", spd_id);

	return err;
}

naas_err_t
naas_api_ipsec_itf_create(int instance, uint32_t *p_sw_if_index)
{
	int msg_id;
	uint32_t sw_if_index;
	naas_err_t err;
	vl_api_ipsec_itf_create_t mp;
	vl_api_ipsec_itf_create_reply_t *rp;

	msg_id = vac_get_msg_index(VL_API_IPSEC_ITF_CREATE_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.itf.mode =  TUNNEL_API_MODE_P2P;
	mp.itf.user_instance = htonl(instance);

	sw_if_index = ~0;
	err.num = 0;

	err = NAAS_API_INVOKE(mp, rp);
	if (err.type == NAAS_ERR_VNET) {
		sw_if_index = ntohl(rp->sw_if_index);
	}
	naas_api_msg_free(rp);

	if (p_sw_if_index != NULL) {
		*p_sw_if_index = sw_if_index;
	}

	naas_err_logf(LOG_INFO, err, "[VPP][API][ipsec_itf_create] instance=%u", instance);

	return err;
}

naas_err_t
naas_api_ipsec_itf_delete(uint32_t sw_if_index)
{
	int msg_id;
	naas_err_t err;
	vl_api_ipsec_itf_delete_t mp;
	vl_api_ipsec_itf_delete_reply_t *rp;

	msg_id = vac_get_msg_index(VL_API_IPSEC_ITF_DELETE_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.sw_if_index = htonl(sw_if_index);

	err = NAAS_API_INVOKE(mp, rp);
	naas_api_msg_free(rp);

	naas_err_logf(LOG_INFO, err, "[VPP][API][ipsec_itf_delete] sw_if_index=%u", sw_if_index);

	return err;
}

typedef struct naas_api_vl_api_ipsec_tunnel_protect_update {
	vl_api_ipsec_tunnel_protect_update_t base;
	uint32_t sa_in;
} naas_api_vl_api_ipsec_tunnel_protect_update_t;

naas_err_t
naas_api_ipsec_tunnel_protect_update(uint32_t sw_if_index, uint32_t sa_in, uint32_t sa_out)
{
	int msg_id;
	naas_err_t err;
	naas_api_vl_api_ipsec_tunnel_protect_update_t mp;
	vl_api_ipsec_tunnel_protect_update_reply_t *rp;

	msg_id = vac_get_msg_index(VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp.base._vl_msg_id = ntohs(msg_id);
	mp.base.tunnel.sw_if_index = htonl(sw_if_index);
	mp.base.tunnel.sa_out = htonl(sa_out);
	mp.base.tunnel.n_sa_in = 1;
	mp.sa_in = htonl(sa_in);	

	err = NAAS_API_INVOKE(mp, rp);
	naas_api_msg_free(rp);

	naas_err_logf(LOG_INFO, err,
"[VPP][API][ipsec_tunnel_protect_update] sw_if_index=%u, sa_in=%u, sa_out=%u",
			sw_if_index, sa_in, sa_out);

	return err;
}

// VPP ctl:
// show ipsec sa
static int
naas_api_ipsec_sa_details(void *user0, void *user, void *data, int len)
{
	uint32_t sad_id, spi;
	naas_api_ipsec_sa_dump_f handler;
	vl_api_ipsec_sa_details_t *details;

	if (len != sizeof(*details)) {
		return -EINVAL;
	}

	handler = user0;
	details = (void *)data;
	sad_id = ntohl(details->entry.sad_id);
	spi = ntohl(details->entry.spi);
	if (handler != NULL) {
		(*handler)(user, sad_id, spi);
	}

	naas_logf(LOG_DEBUG, 0, "[VPP][API][ipsec_sa_dump] sad_id=%u, spi=%x", sad_id, spi);
	return 0;
}

naas_err_t
naas_api_ipsec_sa_dump(naas_api_ipsec_sa_dump_f handler, void *user)
{
	int rc, msg_id;
	naas_err_t err;
	vl_api_ipsec_sa_dump_t mp;

	msg_id = vac_get_msg_index(VL_API_IPSEC_SA_DUMP_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);

	rc = naas_api_dump(&mp, sizeof(mp), VL_API_IPSEC_SA_DETAILS_CRC,
			naas_api_ipsec_sa_details, handler, user);

	err.type = NAAS_ERR_ERRNO;
	err.num = -rc;
	return err;
}

naas_err_t
naas_api_ipip_add_tunnel(int instance, struct in_addr src, struct in_addr dst,
		uint32_t *p_sw_if_index)
{
	int msg_id;
	naas_err_t err;
	uint32_t sw_if_index;
	char srcbuf[INET_ADDRSTRLEN];
	char dstbuf[INET_ADDRSTRLEN];
	vl_api_ipip_add_tunnel_t mp;
	vl_api_ipip_add_tunnel_reply_t *rp;

	msg_id = vac_get_msg_index(VL_API_IPIP_ADD_TUNNEL_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.tunnel.instance = htonl(instance);
	mp.tunnel.src.af = ADDRESS_IP4;
	clib_memcpy(mp.tunnel.src.un.ip4, &src.s_addr, 4);
	mp.tunnel.dst.af = ADDRESS_IP4;
	clib_memcpy(mp.tunnel.dst.un.ip4, &dst.s_addr, 4);
	mp.tunnel.mode = TUNNEL_API_MODE_P2P;

	sw_if_index = ~0;
	err.num = 0;

	err = NAAS_API_INVOKE(mp, rp);
	if (err.type == NAAS_ERR_VNET) {
		sw_if_index = ntohl(rp->sw_if_index);
	}
	naas_api_msg_free(rp);

	if (p_sw_if_index != NULL) {
		*p_sw_if_index = sw_if_index;
	}

	naas_err_logf(LOG_INFO, err,
"[VPP][API][ipip_add_tunnel] instance=%u, src=%s, dst=%s, sw_if_index=%u",
			instance, NAAS_INET_NTOA(&src, srcbuf), NAAS_INET_NTOA(&dst, dstbuf),
			sw_if_index);

	return err;
}
