#include <assert.h>
#include <stdarg.h>
#include <sys/file.h>
#include <net/if.h>
#include <syslog.h>

#include <linux/rtnetlink.h>
#include <linux/lwtunnel.h>
#include <linux/seg6_local.h>

#include <netlink/cli/utils.h>
#include <netlink/cli/link.h>
#include <netlink/cli/mdb.h>
#include <netlink/route/link/vrf.h>

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

#define LCP_DAEMON_NAME "vpp-lcpd"
#define LCP_LOGBUFSZ 256

#ifdef HAVE_SEG6_LOCAL_VRFTABLE
#define LCP_SEG6_LOCAL_VRFTABLE SEG6_LOCAL_VRFTABLE
#else
#define LCP_SEG6_LOCAL_VRFTABLE 9
#endif

#define LCP_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define LCP_MIN(a, b) ((a) < (b) ? (a) : (b))

struct lcp_strbuf;

static void lcp_strbuf_addf(struct lcp_strbuf *sb, const char *format, ...)
	__attribute__((format(printf, 2, 3)));

static void lcp_logf(int level, int errnum, const char *format, ...)
	__attribute__((format(printf, 3, 4)));

struct lcp_strbuf {
	char *sb_buf;
	int sb_len;
	int sb_cap;
};

struct lcp_itf_pair {
	int phy_sw_if_index;
	int host_if_index;
};

int g_lcp_log_level = LOG_INFO;
int g_lcp_vac_callback_msg_id;
int g_vrf_support = 1;
struct lcp_itf_pair g_lcp_itf_pairs[256];
int g_lcp_itf_pair_num; 
int g_tunsrc_set = 1;
void (*g_lcp_vac_callback_fn)(void *data, int len);

static const char *
lcp_bool_str(int b)
{
	return b ? "true" : "false";
}

static void
lcp_strbuf_init(struct lcp_strbuf *sb, char *buf, int bufsz)
{
	assert(bufsz);
	sb->sb_buf = buf;
	sb->sb_cap = bufsz;
	sb->sb_len = 0;
}

static char *
lcp_strbuf_cstr(struct lcp_strbuf *sb)
{
	sb->sb_buf[sb->sb_len < sb->sb_cap ? sb->sb_len : sb->sb_cap - 1] = '\0';
	return sb->sb_buf;
}

static int
lcp_strbuf_space(struct lcp_strbuf *sb)
{
	return sb->sb_cap > sb->sb_len ? sb->sb_cap - sb->sb_len : 0;
}

static void
lcp_strbuf_add(struct lcp_strbuf *sb, const char *buf, int bufsz)
{
	int len, space;

	space = lcp_strbuf_space(sb);
	len = LCP_MIN(bufsz, space);
	memcpy(sb->sb_buf + sb->sb_len, buf, len);
	sb->sb_len += bufsz;
}

static void
lcp_strbuf_adds(struct lcp_strbuf *sb, const char *s)
{
	lcp_strbuf_add(sb, s, strlen(s));
}

static void
lcp_strbuf_vaddf(struct lcp_strbuf *sb, const char *format, va_list ap)
{
	int space, len;

	space = lcp_strbuf_space(sb);
	len = vsnprintf(sb->sb_buf + sb->sb_len, space, format, ap);
	sb->sb_len += len;
}

static void
lcp_strbuf_addf(struct lcp_strbuf *sb, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	lcp_strbuf_vaddf(sb, format, ap);
	va_end(ap);
}

static void
lcp_strbuf_add_inet(struct lcp_strbuf *sb, int family, const void *src)
{
	const char *s;
	char inet_buf[INET6_ADDRSTRLEN];

	s = inet_ntop(family, src, inet_buf, sizeof(inet_buf));
	lcp_strbuf_adds(sb, s);
}

static void
lcp_log_add_error(struct lcp_strbuf *sb, int errnum)
{
	lcp_strbuf_addf(sb, " (%d:%s)", errnum, strerror(errnum));
}

static void
lcp_log_flush(int level, struct lcp_strbuf *sb)
{
	syslog(level, "%s", lcp_strbuf_cstr(sb));
}

static void
lcp_vlogf(int level, int errnum, const char *format, va_list ap)
{
	char log_buf[LCP_LOGBUFSZ];
	struct lcp_strbuf sb;

	if (g_lcp_log_level < level) {
		return;
	}
	lcp_strbuf_init(&sb, log_buf, sizeof(log_buf));
	if (errnum) {
		lcp_log_add_error(&sb, errnum);
		lcp_log_flush(level, &sb);
	} else {
		vsyslog(level, format, ap);
	}
}

static void
lcp_logf(int level, int errnum, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	lcp_vlogf(level, errnum, format, ap);
	va_end(ap);
}

static const char *
lcp_inet6_ntop(const void *in6)
{
	static char in6_buf[INET6_ADDRSTRLEN];

	return inet_ntop(AF_INET6, in6, in6_buf, sizeof(in6_buf));
}

static void
lcp_route_vlogf(int level, int errnum, struct rtnl_route *route, const char *format, va_list ap)
{
	int af, prefixlen;
	void *prefix;
	struct nl_addr *dst;
	struct lcp_strbuf sb;
	char log_buf[LCP_LOGBUFSZ];

	if (g_lcp_log_level < level) {
		return;
	}
	lcp_strbuf_init(&sb, log_buf, sizeof(log_buf));
	lcp_strbuf_adds(&sb, "[NETLINK][ROUTE:");

	dst = rtnl_route_get_dst(route);
	af = rtnl_route_get_family(route);
	prefix = nl_addr_get_binary_addr(dst);
	prefixlen = nl_addr_get_prefixlen(dst);

	lcp_strbuf_add_inet(&sb, af, prefix);
	
	lcp_strbuf_addf(&sb, "/%d]", prefixlen);
	lcp_strbuf_vaddf(&sb, format, ap);
	if (errnum) {
		lcp_log_add_error(&sb, errnum);
	}
	lcp_log_flush(level, &sb);
}

static void
lcp_route_logf(int level, int errnum, struct rtnl_route *route, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	lcp_route_vlogf(level, errnum, route, format, ap);
	va_end(ap);
}

static char *
lcp_rtrim(char *s)
{
	int len;

	len = strlen(s);
	for (;len > 0; --len) {
		if (s[len - 1] != '\n') {
			break;
		}
	}
	s[len] = '\0';
	return s;
}

int
pid_file_open()
{
	int fd, rc, len;
	char path[PATH_MAX];
	char buf[32];

	snprintf(path, sizeof(path), "/var/run/%s.pid", LCP_DAEMON_NAME);

	rc = open(path, O_CREAT|O_RDWR, 0666);
	if (rc == -1) {
		rc = -errno;
		lcp_logf(LOG_ERR, -rc, "open('%s') failed", path);
		return rc;
	}
	fd = rc;
	rc = flock(fd, LOCK_EX|LOCK_NB);
	if (rc == -1) {
		rc = -errno;
	}
	if (rc == -EWOULDBLOCK) {
		lcp_logf(LOG_ERR, 0, "Daemon already running");
		return rc;
	} else if (rc < 0) {
		lcp_logf(LOG_ERR, -rc, "flock('%s') failed", path);
		return rc;
	}
	len = snprintf(buf, sizeof(buf), "%d", (int)getpid());
	rc = write(fd, buf, len);
	if (rc == -1) {
		rc = -errno;
		lcp_logf(LOG_ERR, -rc, "write('%s') failed", path);
		return rc;
	} else {
		return 0;
	}
}

// TODO: Use libnl3 instead of popen(...)
static int
lcp_ip_sr_tunsrc_show(struct in6_addr *tunsrc)
{
	FILE *file;
	int rc, len, rm;
	char buf[INET6_ADDRSTRLEN + 32];
	char *s;

	file = popen("ip sr tunsrc show", "r");
	s = fgets(buf, sizeof(buf), file);
	if (s == NULL) {
		return -errno;
	}	
	s = lcp_rtrim(s);
	len = strlen(s);
	rm = sizeof("tunsrc addr ") - 1;
	if (len < rm) {
		return -EINVAL;
	}
	s += rm;
	rc = inet_pton(AF_INET6, s, tunsrc);
	if (rc != 1) {
		return -EINVAL;
	} else {
		return 0;
	}
}

static void
lcp_vac_callback(unsigned char *data, int len)
{
	g_lcp_vac_callback_msg_id = ntohs(*((u16 *)data));
	if (g_lcp_vac_callback_fn != NULL) {
		(*g_lcp_vac_callback_fn)(data, len);
	}
}

static int
lcp_vac_connect()
{
	int rc;

	clib_mem_init(0, 64 << 20); // 20 Mb

	rc = vac_connect(LCP_DAEMON_NAME, NULL, lcp_vac_callback, 32);
	if (rc != 0) {
		lcp_logf(LOG_ERR, 0, "[VPP] Connection failed");
		return rc;
	}
	lcp_logf(LOG_NOTICE, 0, "[VPP] Connected");
	return 0;
}

static void
lcp_vac_wait(int msg_id)
{
	while (g_lcp_vac_callback_msg_id != msg_id) {
		usleep(1000);
	}
}

static int
get_phy_sw_if_index(int host_if_index)
{
	int i;

	for (i = 0; i < g_lcp_itf_pair_num; ++i) {
		if (g_lcp_itf_pairs[i].host_if_index == host_if_index) {
			return g_lcp_itf_pairs[i].phy_sw_if_index;
		}
	}
	return -1;
}

static void
lcp_itf_pair_details_handler(void *data, int len)
{
	int rc;
	vl_api_lcp_itf_pair_details_t *mp;

	if (len != sizeof(*mp)) {
		return;
	}
	mp = data;
	if (g_lcp_itf_pair_num == LCP_ARRAY_SIZE(g_lcp_itf_pairs)) {
		lcp_logf(LOG_ERR, 0, "[VPP] Too many lcp interfaces");
		return;
	}
	rc = if_nametoindex((const char *)mp->host_if_name);
	if (rc == 0) {
		lcp_logf(LOG_ERR, errno, "if_nametoindex('%s') failed",
				mp->host_if_name);
		return;
	}
	g_lcp_itf_pairs[g_lcp_itf_pair_num].phy_sw_if_index = ntohl(mp->phy_sw_if_index);
	g_lcp_itf_pairs[g_lcp_itf_pair_num].host_if_index = rc;
	lcp_logf(LOG_NOTICE, 0, "[VPP] Enumerate lcp interface '%s': linux_ifindex=%d, vpp_ifindex=%d",
			mp->host_if_name, rc, ntohl(mp->phy_sw_if_index));
	g_lcp_itf_pair_num++;
}

// vat2: lcp_itf_pair_get; cursor = 0
static void
lcp_enumerate_interfaces()
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

	g_lcp_vac_callback_fn = lcp_itf_pair_details_handler;
	vac_write((void *)&mp, sizeof(mp));

	lcp_vac_wait(reply_id);
	g_lcp_vac_callback_fn = NULL;
}

// set sr encaps source addr 2001:db8::1
static void
lcp_set_sr_encaps_source_addr(struct in6_addr *addr)
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

	lcp_vac_wait(reply_id);

	lcp_logf(LOG_INFO, 0, "[VPP] 'set sr encaps source addr' tunsrc=%s",
			lcp_inet6_ntop(addr));
}

// linux:	ip link add dev VRF13 type vrf table 13
// vppctl: 	ip table add 13
//		ip6 table add 13
// vat2: 	'ip_table_add_del' is_add=true, is_ip6=false, table_id=13
static void
lcp_ip_table_add_del(int is_add, int is_ip6, int table_id)
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

	lcp_vac_wait(reply_id);

	lcp_logf(LOG_INFO, 0, "[VPP] 'ip_table_add_del' is_add=%s, is_ip6=%s, table_id=%d",
			lcp_bool_str(is_ip6), lcp_bool_str(is_add), table_id);
}

static int
lcp_sr_action_2_behavior(int action)
{
	switch (action) {
	case SEG6_LOCAL_ACTION_END:
		return SR_BEHAVIOR_API_END;
	case SEG6_LOCAL_ACTION_END_X:
		return SR_BEHAVIOR_API_X;
	case SEG6_LOCAL_ACTION_END_T:
		return SR_BEHAVIOR_API_T;
	case SEG6_LOCAL_ACTION_END_DX2:
		return SR_BEHAVIOR_API_DX2;
	case SEG6_LOCAL_ACTION_END_DX6:
		return SR_BEHAVIOR_API_DX6;
	case SEG6_LOCAL_ACTION_END_DX4:
		return SR_BEHAVIOR_API_DX4;
	case SEG6_LOCAL_ACTION_END_DT4:
		return SR_BEHAVIOR_API_DT4;
	case SEG6_LOCAL_ACTION_END_DT6:
		return SR_BEHAVIOR_API_DT6;
	default:
		return -ENOTSUP;
	}
}

static const char *
lcp_sr_behavior_api_str(int behavior)
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

// Linux:
// ip -6 route add 2000:aaa8:0:0:100::/128 encap seg6local action End.DT6 table 13 dev VRF13
// ip -6 route add 2000:aaa8:0:0:100::/128 encap seg6local action End.DT4 vrftable 13  dev VRF13 
// 
// VPP ctl:
// sr localsid address 2000:aaa8:0:0:100:: behavior end.dt6 13
//
// VPP api:
// 'sr_localsid_add_del' is_del=false, localsid=2000:aaa8:0:0:100::, behavior=SR_BEHAVIOR_API_DT6

static void
lcp_sr_localsid_add_del(int is_add, int action, void *addr, int table_id)
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
	mp.behavior = lcp_sr_action_2_behavior(action);

	vac_write((void *)&mp, sizeof(mp));

	lcp_vac_wait(reply_id);

	lcp_logf(LOG_INFO, 0, "[VPP] 'sr_localsid_add_del' is_del=%s, localsid=%s, sw_if_index=%d, behavior=\"%s\"",
			lcp_bool_str(mp.is_del), lcp_inet6_ntop(mp.localsid), ntohl(mp.sw_if_index),
			lcp_sr_behavior_api_str(mp.behavior));
}

// VPP ctl:
// sr policy add bsid 2000:aaa2:0:0:101:: next 2000:aaa2:0:0:100:: encap
static void
lcp_sr_policy_add(uint8_t *bsid, struct in6_addr *segments, int first_segment)
{
	int i, msg_id, reply_id;
	vl_api_sr_policy_add_t mp;
	api_main_t *am;

	if (first_segment >= LCP_ARRAY_SIZE(mp.sids.sids)) {
		lcp_logf(LOG_ERR, 0, "[VPP] 'sr_policy_add' failed (sids limit exceeded)");
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

	lcp_vac_wait(reply_id);

	lcp_logf(LOG_INFO, 0, "[VPP] 'sr policy add' bsid=%s", lcp_inet6_ntop(bsid));
}

static void
lcp_sr_policy_del(uint8_t *bsid)
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

	lcp_vac_wait(reply_id);

	lcp_logf(LOG_INFO, 0, "[VPP] 'sr policy del' bsid=%s", lcp_inet6_ntop(bsid));
}

// Linux:
// ip r a 10.8.8.0/24 via inet6 fe80::5200:ff:fe03:3766 encap seg6 mode encap segs 2000:aaa2:0:0:100:: dev eth2 table 13
//
// VPP ctl:
// sr steer l3 10.8.8.0/24 via bsid 2000:aaa2:0:0:101:: fib-table 13
// show sr steering-policies
static void
lcp_sr_steering_add_del(int is_add, int phy_sw_if_index,
		int family, void *prefix, int prefixlen,
		int table_id, const uint8_t *bsid)
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

	lcp_vac_wait(reply_id);

	lcp_logf(LOG_INFO, 0, "[VPP] 'sr steering %s' bsid=%s, table_id=%d\n",
			is_add ? "add" : "del", lcp_inet6_ntop(bsid), table_id);
}

static void
lcp_nl_handle_seg6_local(int is_add, struct rtnl_route *route, struct rtnl_nexthop *nh)
{
	int action, table_id;
	struct nl_addr *dst;

	action = rtnl_route_nh_get_encap_seg6_local_action(nh);
	switch (action) {
	case SEG6_LOCAL_ACTION_END_DT6:
	case SEG6_LOCAL_ACTION_END_DT4:
		if (rtnl_route_nh_has_encap_seg6_local_attr(nh, SEG6_LOCAL_TABLE)) {
			table_id = rtnl_route_nh_get_encap_seg6_local_table(nh);
		} else if (rtnl_route_nh_has_encap_seg6_local_attr(nh, LCP_SEG6_LOCAL_VRFTABLE)) {
			table_id = rtnl_route_nh_get_encap_seg6_local_vrftable(nh);
		} else {
			lcp_route_logf(LOG_WARNING, 0, route, "[SEG6_LOCAL] Table not specified");
			break;
		}

		lcp_route_logf(LOG_INFO, 0, route, "[SEG6_LOCAL] %s, table_id=%d",
				is_add ? "Add" : "Del", table_id);

		dst = rtnl_route_get_dst(route);
		assert(nl_addr_get_family(dst) == AF_INET6);
		lcp_sr_localsid_add_del(is_add, action, nl_addr_get_binary_addr(dst), table_id);
		break;

	default:
		lcp_route_logf(LOG_WARNING, 0, route, "[SEG6_LOCAL] Unsupported action: %d",
				action);
		break;
	}
}

static void
lcp_tunsrc_set()
{
	int rc;
	struct in6_addr src;

	if (g_tunsrc_set) {
		return;
	}
	g_tunsrc_set = 1;
	rc = lcp_ip_sr_tunsrc_show(&src);
	if (rc < 0) {
		lcp_logf(LOG_ERR, -rc, "[NETLINK] 'ip sr tunsrc show' failed");
		return;
	}
	lcp_set_sr_encaps_source_addr(&src);
}

static void
lcp_gen_bsid(uint8_t *bsid, const uint8_t *seg1)
{
	int i;

	memcpy(bsid, seg1, 16);
	for (i = 0; i < 8; ++i) {
		if ((bsid[14] & (1 << i)) == 0) {
			bsid[14] |= (1 << i);
			return;
		}
	}
	lcp_logf(LOG_ERR, 0, "Generation of bsid failed, seg1=%s", lcp_inet6_ntop(seg1));
}

static void
lcp_nl_handle_seg6(int is_add, struct rtnl_route *route, struct rtnl_nexthop *nh)
{
	struct ipv6_sr_hdr *srh;
	uint8_t bsid[16];
	int table_id, family, prefixlen, host_if_index, phy_sw_if_index;
	void *prefix;
	struct nl_addr *dst;

	host_if_index = rtnl_route_nh_get_ifindex(nh);
	phy_sw_if_index = get_phy_sw_if_index(host_if_index);
	if (phy_sw_if_index < 0) {
		lcp_route_logf(LOG_DEBUG, 0, route, "[SEG6] Skip interface: ifindex=%d",
				host_if_index);
		return;
	}

	table_id = rtnl_route_get_table(route);

	lcp_route_logf(LOG_INFO, 0, route, "[SEG6] %s, table_id=%d",
			is_add ? "Add" : "Del", table_id);

	dst = rtnl_route_get_dst(route);
	rtnl_route_nh_get_encap_seg6_srh(nh, (void **)&srh);
	family = nl_addr_get_family(dst);
	prefix = nl_addr_get_binary_addr(dst);
	prefixlen = nl_addr_get_prefixlen(dst);

	lcp_gen_bsid(bsid, srh->segments[srh->first_segment].s6_addr);

	if (is_add) {
		lcp_tunsrc_set();
		lcp_sr_policy_add(bsid,	srh->segments, srh->first_segment);
	}

	lcp_sr_steering_add_del(is_add, phy_sw_if_index, family, prefix, prefixlen,
			table_id, bsid);

	if (!is_add) {
		lcp_sr_policy_del(bsid);
	}
}

static void
lcp_nl_handle_nexthop(int is_add, struct rtnl_route *route, struct rtnl_nexthop *nh)
{
	int encap_type;

	encap_type = rtnl_route_nh_get_encap_type(nh);
	switch (encap_type) {
	case LWTUNNEL_ENCAP_SEG6_LOCAL:
		lcp_nl_handle_seg6_local(is_add, route, nh);
		break;

	case LWTUNNEL_ENCAP_SEG6:
		lcp_nl_handle_seg6(is_add, route, nh);
		break;

	default:
		lcp_route_logf(LOG_DEBUG, 0, route, " Unhandled encap type %d", encap_type);
	}
}

static void
lcp_nl_handle_route(int is_add, struct nl_object *obj)
{
	int i, n;
	struct rtnl_route *route;
	struct rtnl_nexthop *nh;

	route = nl_object_priv(obj);
	n = rtnl_route_get_nnexthops(route);
	if (!n) {
		lcp_route_logf(LOG_DEBUG, 0, route, " Route without nexthop");
		return;
	}
	for (i = 0; i < n; ++i) {
		nh = rtnl_route_nexthop_n(route, i);
		lcp_nl_handle_nexthop(is_add, route, nh);
	}
}

static void
obj_input(struct nl_object *obj, void *arg)
{
	int msgtype, is_add;
	uint32_t tableid;
	const char *link_name;
	struct rtnl_link *link;

	msgtype = nl_object_get_msgtype(obj);
	is_add = 1;
	switch (msgtype) {
	case RTM_DELLINK:
		is_add = 0;
	case RTM_NEWLINK:
		if (!g_vrf_support) {
			break;
		}
		link = nl_object_priv(obj);
		link_name = rtnl_link_get_name(link);
		if (rtnl_link_is_vrf(link)) {
			if (!rtnl_link_vrf_get_tableid(link, &tableid)) {
				lcp_ip_table_add_del(is_add, 0, tableid);
				lcp_ip_table_add_del(is_add, 1, tableid);
			} else {
				lcp_logf(LOG_DEBUG, 0, "[NETLINK][LINK:%s] VRF without table",
						link_name);
			}
		} else {
			lcp_logf(LOG_DEBUG, 0, "[NETLINK][LINK:%s] Link is not VRF",
					link_name);
		}
		break;

	case RTM_DELROUTE:
		is_add = 0;
	case RTM_NEWROUTE:
		lcp_nl_handle_route(is_add, obj);
		break;

	default:
		lcp_logf(LOG_DEBUG, 0, "[NETLINK] Unhandled message type %d", msgtype);
		break;
	}
}

static int
event_input(struct nl_msg *msg, void *arg)
{
	nl_msg_parse(msg, &obj_input, arg);
	return NL_STOP;
}

static void
print_usage(void)
{
        printf(
	"Usage: %s [OPTION]\n"
	"\n"
	"Options\n"
	" -h,--help  Show this help\n"
	" -d,--daemonize  Run application in background\n"
	" -l,log-level {err|warning|notice|info|debug}  Set log level, default: info\n"
	"--vrf {0/1}  Set vrf synchronization support, default: 1\n"
	"\n",
	LCP_DAEMON_NAME
        );
        exit(0);
}

int
main(int argc, char **argv)
{
	struct nl_sock *sock;
	int fd, opt, dflag, long_option_index;
	const char *long_option_name;
	fd_set rfds;
	static struct option long_options[] = {
		{"help", no_argument, 0, 'h' },
		{"daemonize", no_argument, 0, 'd' },
		{"log-level", required_argument, 0, 'l' },
		{"vrf", required_argument, 0, 0 },
	};

	dflag = 0;
	while ((opt = getopt_long(argc, argv, "hdl:", long_options, &long_option_index)) != -1) {
		switch (opt) {
		case 0:
			long_option_name = long_options[long_option_index].name;
			if (!strcmp(long_option_name, "vrf"))
				g_vrf_support = strtoul(optarg, NULL, 10);
			return 0;
		case 'd':
			dflag = 1;
			break;

		case 'l':
			if (!strcasecmp(optarg, "err")) {
				g_lcp_log_level = LOG_ERR;
			} else if (!strcasecmp(optarg, "warning")) {
				g_lcp_log_level = LOG_WARNING; 
			} else if (!strcasecmp(optarg, "notice")) {
				g_lcp_log_level = LOG_NOTICE;
			} else if (!strcasecmp(optarg, "info")) {
				g_lcp_log_level = LOG_INFO;
			} else if (!strcasecmp(optarg, "debug")) {
				g_lcp_log_level = LOG_DEBUG;
			} else {
				fprintf(stderr, "-l: Invalid log level '%s'\n", optarg);
				print_usage();
				return EXIT_FAILURE;
			}
			break;

		default:
			print_usage();
			break;
		}
	}

	if (dflag) {
		daemon(0, 0);
	}

	openlog(LCP_DAEMON_NAME, 0, LOG_DAEMON);
	lcp_logf(g_lcp_log_level, 0, "Logging started");

	if (pid_file_open()) {
		return EXIT_FAILURE;
	}

	sock = nl_cli_alloc_socket();
	nl_socket_disable_seq_check(sock);
	nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, event_input, NULL);
	nl_cli_connect(sock, NETLINK_ROUTE);
	nl_socket_add_membership(sock, RTNLGRP_LINK);
	nl_socket_add_membership(sock, RTNLGRP_IPV4_ROUTE);
	nl_socket_add_membership(sock, RTNLGRP_IPV6_ROUTE);

	if (lcp_vac_connect()) {
		return EXIT_FAILURE;
	}

	lcp_enumerate_interfaces();
	if (!g_lcp_itf_pair_num) {
		lcp_logf(LOG_NOTICE, 0, "[VPP] No lcp interfaces found");
	}

	while (1) {
		fd = nl_socket_get_fd(sock);

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		select(fd + 1, &rfds, NULL, NULL, NULL);

		if (FD_ISSET(fd, &rfds)) {
			nl_recvmsgs_default(sock);
		}
	}

	return 0;
}
