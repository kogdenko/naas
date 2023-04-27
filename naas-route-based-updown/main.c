#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <getopt.h>
#include <netinet/in.h>

#include <libvici.h>

#include <libnaas/utils.h>
#include <libnaas/log.h>
#include <libnaas/strbuf.h>
#include <libnaas/list.h>
#include <libnaas/api.h>

#define PROG_NAME "naas-route-based-updown"
#define REQMSG_LEN_MAX 2048

#define REQ_IN 0
#define REQ_OUT 1

struct request {
	struct naas_dlist list;
	uint32_t reqid;
	uint32_t uniqueid;
	struct in_addr me;
	struct in_addr peer;
	struct in_addr peer_client;
	unsigned int peer_client_mask;
	uint32_t spi[2];
	uint32_t sa[2];
	uint8_t has_spi[2];
	uint8_t has_sa[2];
};

static int g_log_inited;
static uint32_t g_loop_sw_if_index;

#define VICI_RESOLVE

static void finalize_request(struct request *req);

#ifdef VICI_RESOLVE
struct list_sa_udata {
	struct naas_dlist *reqq;
	struct naas_dlist *found;
};

static void
list_sa_set_spi(struct list_sa_udata *udata, uint32_t reqid, int dir, uint32_t spi)
{
	struct request *req, *tmp;

	naas_logf(LOG_DEBUG, 0, "vici: list_sa: reqid=%u, spi=%u", reqid, spi);

	NAAS_DLIST_FOREACH_SAFE(req, udata->reqq, list, tmp) {
		if (reqid == req->reqid) {
			req->spi[dir] = spi;
			req->has_spi[dir] = 1;
			if (req->has_spi[!dir]) {
				NAAS_DLIST_REMOVE(req, list);
				NAAS_DLIST_INSERT_TAIL(udata->found, req, list);
			}
		}
	}
}

static void
list_sa(void *user, char *name, vici_res_t *res)
{
	int dir;
	uint32_t reqid, spi;
	char *key, *value;
	vici_parse_t rc;
	struct list_sa_udata *udata;

	udata = user;
	reqid = -1;
	for (;;) {
		rc = vici_parse(res);
		switch (rc) {
		case VICI_PARSE_END:
		case VICI_PARSE_ERROR:
			return;
		case VICI_PARSE_BEGIN_SECTION:
			vici_parse_name(res);
			break;
		case VICI_PARSE_KEY_VALUE:
			key = vici_parse_name(res);
			value = vici_parse_value_str(res);
			if (!strcmp(key, "reqid")) {
				reqid = strtoul(value, NULL, 10);
			} else if (!strcmp(key, "spi-out") || !strcmp(key, "spi-in")) {
				dir = !strcmp(key, "spi-in") ? REQ_IN : REQ_OUT;
				spi = strtoul(value, NULL, 16);
				list_sa_set_spi(udata, reqid, dir, spi);
			}
			break;
		default:
			break;
		}
	}
}

static int
list_sas(struct naas_dlist *reqq, struct naas_dlist *found)
{
	int rc;
	vici_conn_t *conn;
	vici_req_t *req;
	vici_res_t *res;
	struct list_sa_udata udata;

	vici_init();
	conn = vici_connect(NULL);
	if (!conn) {
		rc = -errno;
		naas_logf(LOG_ERR, "vici_connect() failed");
		return rc;
	}

	udata.reqq = reqq;
	udata.found = found;
	rc = vici_register(conn, "list-sa", list_sa, &udata);
	if (rc != 0) {
		rc = -errno;
		naas_logf(LOG_ERR, "vici_register() failed");
		goto err;
	}

	req = vici_begin("list-sas");
	vici_add_key_valuef(req, "noblock", "yes");

	res = vici_submit(req, conn);
	if (res) {
		vici_free_res(res);
	} else {
		rc = -errno;
		naas_logf(LOG_ERR, "vici_submit() failed");
	}
err:
	vici_deinit();
	return rc;
}

static void
ipsec_sa_dump_handler(void *user, uint32_t sad_id, uint32_t spi)
{
	int dir;
	struct naas_dlist *head;
	struct request *req;

	head = user;
	NAAS_DLIST_FOREACH(req, head, list) {
		for (dir = 0; dir < 2; ++dir) {
			if (req->spi[dir] == spi) {
				req->sa[dir] = sad_id;
				req->has_sa[dir] = 1;
			}
		}
	}
}

static void
search_sa(struct naas_dlist *reqq)
{
	int dir;
	struct naas_dlist found;
	struct request *req, *tmp;

	naas_dlist_init(&found);

	list_sas(reqq, &found);

	if (naas_dlist_is_empty(&found)) {
		return;
	}

	naas_api_ipsec_sa_dump(ipsec_sa_dump_handler, &found);

	NAAS_DLIST_FOREACH_SAFE(req, &found, list, tmp) {
		for (dir = 0; dir < 2; ++dir) {
			if (!req->has_sa[dir]) {
				naas_logf(LOG_ERR, 0, "%u: No sa_%s (spi=%x)", req->reqid,
						dir == REQ_IN ? "in" : "out", req->spi[dir]);
				break;
			}
		}
		if (dir == 2) {
			finalize_request(req);
		}
		NAAS_DLIST_REMOVE(req, list);
		free(req);
	}
}
#endif // VICI_RESOLVE

static void
sw_interface_details(void *user, struct naas_api_sw_interface *interface)
{
	int *sw_if_index;

	sw_if_index = user;

	*sw_if_index = interface->sw_if_index;
}

static int
get_sw_if_index(const char *loop)
{
	int sw_if_index;

	naas_api_sw_interface_dump(sw_interface_details, &sw_if_index, loop);

	if (sw_if_index < 0) {
		naas_logf(LOG_ERR, 0, "Cannot find interface: '%s'", loop);
		return -ESRCH;
	}

	return sw_if_index;
}

static void
finalize_request(struct request *req)
{
	int ipip_sw_if_index;
	naas_err_t err;
	struct naas_ipip_add_tunnel_ret naas_ipip_add_tunnel_ret;

	err = naas_api_ipip_add_tunnel(req->reqid, req->me, req->peer, &naas_ipip_add_tunnel_ret);
	ipip_sw_if_index = naas_ipip_add_tunnel_ret.sw_if_index;
	if (ipip_sw_if_index == ~0) {
		naas_err_logf(LOG_ERR, err, "ipip_add_tunnel() failed");
		return;
	}

	naas_api_sw_interface_set_unnumbered(1, g_loop_sw_if_index, ipip_sw_if_index);
	naas_api_sw_interface_set_flags(ipip_sw_if_index, IF_STATUS_API_FLAG_ADMIN_UP);
	naas_api_ip_route_add_del(1, req->peer_client, req->peer_client_mask, ipip_sw_if_index);
	naas_api_ipsec_tunnel_protect_update(ipip_sw_if_index,
			req->sa[REQ_IN], req->sa[REQ_OUT]);
}

static int
init(int log_options, const char *loop)
{
	int rc;

	if (!g_log_inited) {
		g_log_inited = 1;
		naas_log_init(PROG_NAME, log_options);
	}

	rc = naas_api_init(PROG_NAME);
	if (rc < 0) {
		return rc;
	}

	rc = get_sw_if_index(loop);
	if (rc < 0) {
		return rc;
	}

	g_loop_sw_if_index = rc;

	// Do we need to up interface ???
	//naas_api_sw_interface_set_flags(g_loop_sw_if_index, IF_STATUS_API_FLAG_ADMIN_UP);

	return 0;
}

static void
deinit(void)
{
	naas_api_deinit();
}

static int
listen_onlocalport(int port)
{
	int rc, fd, opt, flags;
	struct sockaddr_in sin;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(port);
	rc = socket(AF_INET, SOCK_STREAM, 0);
	if (rc == -1) {
		rc = -errno;
		naas_errno_logf(LOG_ERR, errno, "socket(AF_INET, SOCK_STREAM) failed");
		return rc;
	}
	opt = 1;
	fd = rc;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
	rc = bind(fd, (struct sockaddr *)&sin, sizeof(sin));
	if (rc == -1) {
		rc = -errno;
		naas_errno_logf(LOG_ERR, errno, "bind() failed");
		goto err;
	}
	rc = listen(fd, 5);
	if (rc == -1) {
		rc = -errno;
		naas_errno_logf(LOG_ERR, errno, "listen() failed");
		goto err;
	}
	rc = fcntl(fd, F_GETFL, 0);
	if (rc == -1) {
		rc = -errno;
		naas_errno_logf(LOG_ERR, errno, "fcntl(F_GETFL) failed");
		goto err;
	}
	flags = rc|O_NONBLOCK;
	rc = fcntl(fd, F_SETFL, flags);
	if (rc == -1) {
		rc = -errno;
		naas_errno_logf(LOG_ERR, errno, "fcntl(F_SETFL) failed");
		goto err;
	}

	return fd;

err:
	close(fd);
	return rc;
}

static int
connect_tolocalport(int port)
{
	int rc, fd;
	struct sockaddr_in sin;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(port);
	rc = socket(AF_INET, SOCK_STREAM, 0);
	if (rc == -1) {
		rc = -errno;
		naas_errno_logf(LOG_ERR, errno, "socket(AF_INET, SOCK_STREAM) failed");
		return rc;
	}
	fd = rc;
	rc = connect(fd, (struct sockaddr *)&sin, sizeof(sin));
	if (rc == -1) {
		rc = -errno;
		naas_errno_logf(LOG_ERR, errno, "connect() failed");
		close(fd);
		return rc;
	}
	return fd;
}

static int
read_request(int fd, char *buf, int buflen)
{
	int i, rc, len;

	len = 0;
	while (1) {
		rc = read(fd, buf + len, buflen - len - 1);
		if (rc == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				return -errno;
			}
		} else if (rc == 0) {
			break;
		} else {
			for (i = 0; i < rc; ++i, ++len) {	
				if (buf[len] == '\n') {
					goto out;
				}
			}
		}
	}
out:
	buf[len] = '\0';
	return len;
}

static int
send_request(int fd, uint32_t reqid, uint32_t uniqueid, struct in_addr me, struct in_addr peer,
		struct in_addr peer_client, unsigned int peer_client_mask)
{
	int rc;
	char req[REQMSG_LEN_MAX];
	struct naas_strbuf sb;

	naas_strbuf_init(&sb, req, sizeof(req));
	naas_strbuf_addf(&sb, "%u %u %s ", reqid, uniqueid, inet_ntoa(me));
	naas_strbuf_addf(&sb, "%s ", inet_ntoa(peer));
	naas_strbuf_addf(&sb, "%s/%u\n", inet_ntoa(peer_client), peer_client_mask);

	rc = send(fd, naas_strbuf_cstr(&sb), sb.sb_len, 0);
	if (rc < 0) {
		rc = -errno;
		naas_errno_logf(LOG_ERR, errno, "send() failed");
	} else {
		rc = 0;
	}

	naas_errno_logf(LOG_DEBUG, -rc, "send request: '%s'", naas_strbuf_cstr(&sb));

	return rc;
}

static void
handle_request(struct naas_dlist *reqq, char *reqmsg, int reqmsg_len)
{
	int i, argc;
	unsigned int peer_client_mask;
	uint32_t reqid, uniqueid;
	struct in_addr me, peer, peer_client;
	struct request *req;
	char *s, *argv[5];

	argc = 0;	
	for (s = strtok(reqmsg, " \r\n\t"); s != NULL; s = strtok(NULL, " \r\n\t")) {
		if (argc < NAAS_ARRAY_SIZE(argv)) {
			argv[argc++] = s;
		}
	}

	if (argc < 5) {
		goto err;
	}
	reqid = strtoul(argv[0], NULL, 10);
	uniqueid = strtoul(argv[1], NULL, 10);
	if (naas_inet_aton(argv[2], &me, NULL)) {
		goto err;
	}
	if (naas_inet_aton(argv[3], &peer, NULL)) {
		goto err;
	}
	if (naas_inet_aton(argv[4], &peer_client, &peer_client_mask)) {
		goto err;
	}

	naas_logf(LOG_DEBUG, 0, "recv request: %s %s %s %s %s",
			argv[0], argv[1], argv[2], argv[3], argv[4]);
	
	req = naas_xmalloc(sizeof(*req));
	memset(req, 0, sizeof(*req));
	req->reqid = reqid;
	req->uniqueid = uniqueid;
	req->me = me;
	req->peer = peer;
	req->peer_client = peer_client;
	req->peer_client_mask = peer_client_mask;
#ifdef VICI_RESOLVE
	NAAS_DLIST_INSERT_TAIL(reqq, req, list);
#else
	req->sa[REQ_IN] = 1;
	req->sa[REQ_OUT] = 2;
	finalize_request(req);
#endif
	return;

err:
	for (i = 0; i < reqmsg_len; ++i) {
		if (reqmsg[i] == '\0') {
			reqmsg[i] = ' ';
		}
	}
	naas_logf(LOG_ERR, 0, "Bad request: '%s'", reqmsg);
}

static void
server_loop(lfd)
{
	int rc, fd;
	char reqmsg[REQMSG_LEN_MAX];
	fd_set rfds;
	struct naas_dlist reqq;
	struct timeval to;

	naas_dlist_init(&reqq);
	while (1) {
		FD_ZERO(&rfds);
		FD_SET(lfd, &rfds);
		to.tv_sec = 0;
		to.tv_usec = 10000;
		select(lfd + 1, &rfds, NULL, NULL, &to);
		if (FD_ISSET(lfd, &rfds)) {
			fd = accept(lfd, NULL, NULL);
			if (fd >= 0) {
				rc = read_request(fd, reqmsg, sizeof(reqmsg));
				if (rc > 0) {
					handle_request(&reqq, reqmsg, rc);
				}
				close(fd);
			}
		}

#ifdef VICI_RESOLVE
		if (!naas_dlist_is_empty(&reqq)) {
			search_sa(&reqq);
		}
#endif
	}
}

static void
print_usage()
{
        printf(
	"Usage: %s [OPTION]\n"
	"\n"
	"Options\n"
	" -h,--help  Show this help\n"
	" -d,--daemonize  Run application in background\n"
	" -L {port}  Listen on local port\n"
	" -C {port}  Connect to port and send request\n"
	" -l,--log-level {err|warning|notice|info|debug}  Set log level, default: info\n"
	"--log-console  Write log to system console\n"
	"--reqid {number}\n"
	"\n",
	PROG_NAME
        );
}

int
main(int argc, char **argv)
{
	int rc, fd, dflag, Lflag, Cflag, opt, reqid, uniqueid,
			long_option_index, log_options, log_level;
	unsigned int peer_client_mask;
	const char *long_option_name, *loop;
	struct in_addr me, peer, peer_client;
	static struct option long_options[] = {
		{"help", no_argument, 0, 'h' },
		{"daemonize", no_argument, 0, 'd' },
		{"log-level", required_argument, 0, 'l' },
		{"log-console", no_argument, 0, 0 },
		{"reqid", required_argument, 0, 0 },
		{"uniqueid", required_argument, 0, 0 },
		{"me", required_argument, 0, 0 },
		{"peer", required_argument, 0, 0 },
		{"peer-client", required_argument, 0, 0 },
		{"loop", required_argument, 0, 0 },
	};

	dflag = 0;
	Lflag = 0;
	Cflag = 0;
	log_options = 0;
	reqid = -1;
	uniqueid = -1;
	loop = NULL;
	me.s_addr = peer.s_addr = peer_client.s_addr = INADDR_NONE;
	while ((opt = getopt_long(argc, argv, "hdL:C:l:", long_options, &long_option_index)) != -1) {
		switch (opt) {
		case 0:
			long_option_name = long_options[long_option_index].name;
			if (!strcmp(long_option_name, "log-console")) {
				log_options = LOG_CONS;
			} else if (!strcmp(long_option_name, "reqid")) {
				reqid = strtoul(optarg, NULL, 10);
			} else if (!strcmp(long_option_name, "uniqueid")) {
				uniqueid = strtoul(optarg, NULL, 10);
			} else if (!strcmp(long_option_name, "me")) {
				if (naas_inet_aton(optarg, &me, NULL)) {
					naas_print_invalidarg("--me", optarg);
					return EXIT_FAILURE;
				}
			} else if (!strcmp(long_option_name, "peer")) {
				if (naas_inet_aton(optarg, &peer, NULL)) {
					naas_print_invalidarg("--peer", optarg);
					return EXIT_FAILURE;
				}
			} else if (!strcmp(long_option_name, "peer-client")) {
				if (naas_inet_aton(optarg, &peer_client, &peer_client_mask)) {
					naas_print_invalidarg("--peer-client", optarg);
					return EXIT_FAILURE;
				}
			} else if (!strcmp(long_option_name, "loop")) {
				loop = optarg;
			}
			break;
		case 'd':
			dflag = 1;
			break;			
		case 'L':
			Lflag = strtoul(optarg, NULL, 10);
			break;
		case 'C':
			Cflag = strtoul(optarg, NULL, 10);
			break;	
		case 'l':
			log_level = naas_log_level_from_string(optarg);
			if (log_level < 0) {
				naas_print_invalidarg("-l", optarg);
				print_usage();
				return EXIT_FAILURE;
			}
			naas_set_log_level(log_level);
			break;
		case 'h':
			print_usage();
			break;
		}
	}

	if (Lflag) {
		if (loop == NULL) {
			naas_print_unspecifiedarg("--loop");
			print_usage();
			return EXIT_FAILURE;
		}

		if (dflag) {
			daemon(0, 0);
		}
		rc = init(log_options, loop);
		if (rc) {
			return EXIT_FAILURE;
		}
		rc = listen_onlocalport(Lflag);
		if (rc < 0) {
			deinit();
			return EXIT_FAILURE;
		}
		server_loop(rc);
		deinit();
	} else {
		if (!Cflag) {
			print_usage();
			return EXIT_FAILURE;
		}

		if (reqid < 0) {
			naas_print_unspecifiedarg("--reqid");
			print_usage();
			return EXIT_FAILURE;
		}

		if (uniqueid < 0) {
			naas_print_unspecifiedarg("--uniqueid");
			print_usage();
			return EXIT_FAILURE;
		}

		if (me.s_addr == INADDR_NONE) {
			naas_print_unspecifiedarg("--me");
			print_usage();
			return EXIT_FAILURE;
		}

		if (peer.s_addr == INADDR_NONE) {
			naas_print_unspecifiedarg("--peer");
			print_usage();
			return EXIT_FAILURE;
		}

		rc = connect_tolocalport(Cflag);
		if (rc > 0) {
			fd = rc;
			rc = send_request(fd, reqid, uniqueid, me, peer,
					peer_client, peer_client_mask);
			close(fd);
		}
	}

	return rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
