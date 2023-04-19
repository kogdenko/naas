#include <assert.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/file.h>
#include <arpa/inet.h>

#include <linux/rtnetlink.h>
#include <linux/lwtunnel.h>
#include <linux/seg6_local.h>

#include <netlink/cli/utils.h>
#include <netlink/cli/link.h>
#include <netlink/cli/mdb.h>
#include <netlink/route/link/vrf.h>

#include <libnaas/utils.h>
#include <libnaas/strbuf.h>
#include <libnaas/log.h>
#include <libnaas/list.h>
#include <libnaas/api.h>

#define LCP_DAEMON_NAME "vpp-lcpd"

#ifdef HAVE_SEG6_LOCAL_VRFTABLE
#define LCP_SEG6_LOCAL_VRFTABLE SEG6_LOCAL_VRFTABLE
#else
#define LCP_SEG6_LOCAL_VRFTABLE 9
#endif

struct lcp_itf_pair {
	struct naas_dlist list;
	int phy_sw_if_index;
	int host_if_index;
};

int g_vrf_support = 1;
struct naas_dlist g_lcp_itf_pair_head;
int g_tunsrc_set = 1;

static int
sr_action_2_behavior(int action)
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

static void
lcp_route_vlogf(int level, int errnum, struct rtnl_route *route, const char *format, va_list ap)
{
	int af, prefixlen;
	void *prefix;
	struct nl_addr *dst;
	struct naas_strbuf sb;
	char log_buf[NAAS_LOGBUFSZ];

	if (naas_get_log_level() < level) {
		return;
	}
	naas_strbuf_init(&sb, log_buf, sizeof(log_buf));
	naas_strbuf_adds(&sb, "[NETLINK][ROUTE:");

	dst = rtnl_route_get_dst(route);
	af = rtnl_route_get_family(route);
	prefix = nl_addr_get_binary_addr(dst);
	prefixlen = nl_addr_get_prefixlen(dst);

	naas_strbuf_add_inet(&sb, af, prefix);
	
	naas_strbuf_addf(&sb, "/%d]", prefixlen);
	naas_strbuf_vaddf(&sb, format, ap);
	if (errnum) {
		naas_log_add_error(&sb, errnum);
	}
	naas_log_flush(level, &sb);
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
		naas_logf(LOG_ERR, -rc, "open('%s') failed", path);
		return rc;
	}
	fd = rc;
	rc = flock(fd, LOCK_EX|LOCK_NB);
	if (rc == -1) {
		rc = -errno;
	}
	if (rc == -EWOULDBLOCK) {
		naas_logf(LOG_ERR, 0, "Daemon already running");
		return rc;
	} else if (rc < 0) {
		naas_logf(LOG_ERR, -rc, "flock('%s') failed", path);
		return rc;
	}
	len = snprintf(buf, sizeof(buf), "%d", (int)getpid());
	rc = write(fd, buf, len);
	if (rc == -1) {
		rc = -errno;
		naas_logf(LOG_ERR, -rc, "write('%s') failed", path);
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

static int
get_phy_sw_if_index(int host_if_index)
{
	struct lcp_itf_pair *itp;

	NAAS_DLIST_FOREACH(itp, &g_lcp_itf_pair_head, list) {
		if (itp->host_if_index == host_if_index) {
			return itp->phy_sw_if_index;
		}
	}
	return -1;
}

static void
lcp_nl_handle_seg6_local(int is_add, struct rtnl_route *route, struct rtnl_nexthop *nh)
{
	int action, behavior, table_id;
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
		behavior = sr_action_2_behavior(action);
		assert(behavior >= 0);
		naas_api_sr_localsid_add_del(is_add, behavior, nl_addr_get_binary_addr(dst), table_id);
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
		naas_logf(LOG_ERR, -rc, "[NETLINK] 'ip sr tunsrc show' failed");
		return;
	}
	naas_api_set_sr_encaps_source_addr(&src);
}

static void
lcp_gen_bsid(uint8_t *bsid, const uint8_t *seg1)
{
	int i;
	char seg1_addrstr[INET6_ADDRSTRLEN];

	memcpy(bsid, seg1, 16);
	for (i = 0; i < 8; ++i) {
		if ((bsid[14] & (1 << i)) == 0) {
			bsid[14] |= (1 << i);
			return;
		}
	}
	naas_logf(LOG_ERR, 0, "Generation of bsid failed, seg1=%s",
			naas_inet6_ntop(seg1, seg1_addrstr));
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
		naas_api_sr_policy_add(bsid, srh->segments, srh->first_segment);
	}

	naas_api_sr_steering_add_del(is_add, phy_sw_if_index, family, prefix, prefixlen,
			table_id, bsid);

	if (!is_add) {
		naas_api_sr_policy_del(bsid);
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
				naas_api_ip_table_add_del(is_add, 0, tableid);
				naas_api_ip_table_add_del(is_add, 1, tableid);
			} else {
				naas_logf(LOG_DEBUG, 0, "[NETLINK][LINK:%s] VRF without table",
						link_name);
			}
		} else {
			naas_logf(LOG_DEBUG, 0, "[NETLINK][LINK:%s] Link is not VRF",
					link_name);
		}
		break;

	case RTM_DELROUTE:
		is_add = 0;
	case RTM_NEWROUTE:
		lcp_nl_handle_route(is_add, obj);
		break;

	default:
		naas_logf(LOG_DEBUG, 0, "[NETLINK] Unhandled message type %d", msgtype);
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
lcp_itf_pair_get_handler(void *user, int phy_sw_if_index, int host_if_index)
{
	struct naas_dlist *head;
	struct lcp_itf_pair *itp;

	head = user;

	itp = naas_xmalloc(sizeof(*itp));

	itp->phy_sw_if_index = phy_sw_if_index;
	itp->host_if_index = host_if_index;

	NAAS_DLIST_INSERT_TAIL(head, itp, list); 
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
	" -l,--log-level {err|warning|notice|info|debug}  Set log level, default: info\n"
	"--log-console  Write log to system console\n"
	"--vrf {0/1}  Set vrf synchronization support, default: 1\n"
	"\n",
	LCP_DAEMON_NAME
        );
}

int
main(int argc, char **argv)
{
	struct nl_sock *sock;
	int fd, opt, dflag, long_option_index, log_options, log_level;
	const char *long_option_name;
	fd_set rfds;
	static struct option long_options[] = {
		{"help", no_argument, 0, 'h' },
		{"daemonize", no_argument, 0, 'd' },
		{"log-level", required_argument, 0, 'l' },
		{"log-console", no_argument, 0, 0 },
		{"vrf", required_argument, 0, 0 },
	};

	log_options = 0;
	dflag = 0;
	while ((opt = getopt_long(argc, argv, "hdl:", long_options, &long_option_index)) != -1) {
		switch (opt) {
		case 0:
			long_option_name = long_options[long_option_index].name;
			if (!strcmp(long_option_name, "vrf")) {
				g_vrf_support = strtoul(optarg, NULL, 10);
			} else if (!strcmp(long_option_name, "log-console")) {
				log_options = LOG_CONS;
			}
			break;

		case 'd':
			dflag = 1;
			break;

		case 'l':
			log_level = naas_log_level_from_string(optarg);
			if (log_level < 0) {
				naas_print_invalidarg("-l", optarg);
				print_usage();
				return EXIT_FAILURE;
			}
			break;

		default:
			print_usage();
			return EXIT_SUCCESS;
		}
	}

	if (dflag) {
		daemon(0, 0);
	}

	naas_log_init(LCP_DAEMON_NAME, log_options);

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

	if (naas_api_init(LCP_DAEMON_NAME)) {
		return EXIT_FAILURE;
	}

	naas_dlist_init(&g_lcp_itf_pair_head);	
	naas_api_lcp_itf_pair_get(lcp_itf_pair_get_handler, &g_lcp_itf_pair_head);
	if (naas_dlist_is_empty(&g_lcp_itf_pair_head)) {
		naas_logf(LOG_NOTICE, 0, "[VPP] No lcp interfaces found");
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
