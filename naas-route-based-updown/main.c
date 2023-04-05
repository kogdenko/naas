#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <getopt.h>
#include <netinet/in.h>

#include <libvici.h>

#include <naas-common/utils.h>
#include <naas-common/log.h>
#include <naas-common/strbuf.h>
#include <naas-vpp/api.h>

#define PROG_NAME "naas-route-based-updown"
#define REQBUFLEN 2048

struct ipsec_sa_data {
	uint32_t spi_in;
	uint32_t sa_in;
	uint32_t spi_out;
	uint32_t sa_out;
};

struct list_sa_parser {
	int reqid;
	int inout_mask;
	int spi_in;
	int spi_out;
};

void
list_sa(void *user, char *name, vici_res_t *res)
{
	int reqid;
	char *key, *value;
	struct list_sa_parser *parser;
	vici_parse_t rc;

	parser = user;
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
			} else if (!strcmp(key, "spi-in")) {
				if (reqid == parser->reqid) {
					parser->spi_in = strtoul(value, NULL, 16);
					parser->inout_mask |= (1 << 0);
				}
			} else if (!strcmp(key, "spi-out")) {
				if (reqid == parser->reqid) {
					parser->spi_out = strtoul(value, NULL, 16);
					parser->inout_mask |= (1 << 1);
				}
			}
			break;
		default:
			break;
		}
	}
}

static int
get_spi_inout(int reqid, uint32_t *spi_in, uint32_t *spi_out)
{
	int rc;
	vici_conn_t *conn;
	vici_req_t *req;
	vici_res_t *res;
	struct list_sa_parser parser;

	vici_init();
	conn = vici_connect(NULL);
	if (!conn) {
		rc = -errno;
		naas_logf(LOG_ERR, errno, "vici_connect() failed");
		return rc;
	}

	parser.reqid = reqid;
	parser.inout_mask = 0;

	rc = vici_register(conn, "list-sa", list_sa, &parser);
	if (rc != 0) {
		rc = -errno;
		naas_logf(LOG_ERR, errno, "vici_register() failed");
		goto err;
	}

	req = vici_begin("list-sas");	
	res = vici_submit(req, conn);

	if (res) {
		if (parser.inout_mask != 3) {
			rc = -ESRCH;
		} else {
			if (spi_in != NULL) {
				*spi_in = parser.spi_in;
			}
			if (spi_out != NULL) {
				*spi_out = parser.spi_out;
			}
		}
		vici_free_res(res);
	} else {
		rc = -errno;
		naas_logf(LOG_ERR, errno, "vici_submit() failed");
	}
err:
	vici_deinit();
	return rc;
}

static void
ipsec_sa_dump_handler(void *user, uint32_t sad_id, uint32_t spi)
{
	struct ipsec_sa_data *sa_data;

	sa_data = user;
	if (sa_data->spi_in == spi) {
		sa_data->sa_in = sad_id;
	}
	if (sa_data->spi_out == spi) {
		sa_data->sa_out = sad_id;
	}
}

struct sw_interface_dump_ret {
	int sw_if_index;
	char interface_name[NAAS_API_INTERFACE_NAME_MAX];
};

static void
sw_interface_details(void *user, struct naas_api_sw_interface *interface)
{
	struct sw_interface_dump_ret *ret;

	ret = user;
	if (!strcmp(ret->interface_name, interface->interface_name)) {
		ret->sw_if_index = interface->sw_if_index;
	}
}

static int
tunnel_protect(uint32_t reqid, int ipip_sw_if_index)
{
	int rc;
	struct ipsec_sa_data sa_data;

	rc = get_spi_inout(reqid, &sa_data.spi_in, &sa_data.spi_out);
	if (rc != 0) {
		naas_logf(LOG_ERR, -rc, "Cannot find spi by reqid: %d", reqid);
		return rc;
	}

	sa_data.sa_in = -1;
	sa_data.sa_out = -1;
	naas_api_ipsec_sa_dump(ipsec_sa_dump_handler, &sa_data);	
	if (sa_data.sa_in == -1) {
		naas_logf(LOG_ERR, 0, "Cannot find sa_in by spi: %x", sa_data.spi_in);
		return -ESRCH;
	}
	if (sa_data.sa_out == -1) {
		naas_logf(LOG_ERR, 0, "Cannot find sa_out by spi: %x", sa_data.spi_out);
		return -ESRCH;
	}

	rc = naas_api_ipsec_tunnel_protect_update(ipip_sw_if_index,
			sa_data.sa_in, sa_data.sa_out);
	if (rc != 0) {
		naas_logf(LOG_ERR, -rc, "ipsec_tunnel_protect_update() failed");
		return rc;
	}

	return 0;
}

static int
route_based_updown(uint32_t reqid, struct in_addr me, struct in_addr peer,
		struct in_addr peer_client, unsigned int peer_client_mask, const char *loop)
{
	int rc, loop_sw_if_index, ipip_sw_if_index;
	struct sw_interface_dump_ret sw_interface_dump_ret;
	struct naas_ipip_add_tunnel_ret naas_ipip_add_tunnel_ret;

	naas_strzcpy(sw_interface_dump_ret.interface_name, loop,
			sizeof(sw_interface_dump_ret.interface_name));
	sw_interface_dump_ret.sw_if_index = -1;
	naas_api_sw_interface_dump(sw_interface_details, &sw_interface_dump_ret);

	if (sw_interface_dump_ret.sw_if_index < 0) {
		naas_logf(LOG_ERR, 0, "Cannot find interface: '%s'", loop);
		return -ESRCH;
	}
	loop_sw_if_index = sw_interface_dump_ret.sw_if_index;

	rc = naas_ipip_add_tunnel(reqid, me, peer, &naas_ipip_add_tunnel_ret);
	if (rc != 0) {
		naas_logf(LOG_ERR, -rc, "ipip_add_tunnel() failed");
		return rc;
	}
	ipip_sw_if_index = naas_ipip_add_tunnel_ret.sw_if_index;


	rc = naas_api_sw_interface_set_unnumbered(1, loop_sw_if_index, ipip_sw_if_index);
	if (rc != 0) {
		naas_logf(LOG_ERR, -rc, "sw_interface_set_unnumbered() failed");
		return rc;
	}

	rc = naas_api_sw_interface_set_flags(ipip_sw_if_index, IF_STATUS_API_FLAG_ADMIN_UP);
	if (rc != 0) {
		naas_logf(LOG_ERR, -rc, "sw_interface_set_flags() failed");
		return rc;
	}

	rc = naas_api_ip_route_add_del(1, peer_client, peer_client_mask, ipip_sw_if_index);
	if (rc != 0) {
		naas_logf(LOG_ERR, -rc, "ip_route_add_del() failed");
		return rc;
	}

	rc = tunnel_protect(reqid, ipip_sw_if_index);
	return rc;
}

static int
init(int log_options)
{
	int rc;

	naas_log_init(PROG_NAME, log_options);
	rc = naas_api_init(PROG_NAME);
	return rc;
}

static void
deinit(void)
{
	naas_api_deinit();
}

static int
listen_onlocalport(int port)
{
	int rc, fd, opt;
	struct sockaddr_in sin;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(port);
	rc = socket(AF_INET, SOCK_STREAM, 0);
	if (rc == -1) {
		rc = -errno;
		naas_logf(LOG_ERR, errno, "socket(AF_INET, SOCK_STREAM) failed");
		return rc;
	}
	opt = 1;
	fd = rc;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
	rc = bind(fd, (struct sockaddr *)&sin, sizeof(sin));
	if (rc == -1) {
		rc = -errno;
		naas_logf(LOG_ERR, errno, "bind() failed");
		close(fd);
		return rc;
	}
	rc = listen(fd, 5);
	if (rc == -1) {
		rc = -errno;
		naas_logf(LOG_ERR, errno, "listen() failed");
		close(fd);
		return rc;
	}
	return fd;
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
		naas_logf(LOG_ERR, errno, "socket(AF_INET, SOCK_STREAM) failed");
		return rc;
	}
	fd = rc;
	rc = connect(fd, (struct sockaddr *)&sin, sizeof(sin));
	if (rc == -1) {
		rc = -errno;
		naas_logf(LOG_ERR, errno, "connect() failed");
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
send_request(int fd, uint32_t reqid, struct in_addr me, struct in_addr peer,
		struct in_addr peer_client, unsigned int peer_client_mask, const char *loop)
{
	int rc;
	char req[REQBUFLEN];
	struct naas_strbuf sb;

	naas_strbuf_init(&sb, req, sizeof(req));
	naas_strbuf_addf(&sb, "%u %s ", reqid, inet_ntoa(me));
	naas_strbuf_addf(&sb, "%s ", inet_ntoa(peer));
	naas_strbuf_addf(&sb, "%s/%u %s\n", inet_ntoa(peer_client), peer_client_mask, loop);

	rc = send(fd, naas_strbuf_cstr(&sb), sb.sb_len, 0);
	if (rc < 0) {
		rc = -errno;
		naas_logf(LOG_ERR, errno, "send() failed");
	} else {
		rc = 0;
	}
	return rc;
}

int
handle_request(char *req)
{
	int rc, argc;
	unsigned int peer_client_mask;
	uint32_t reqid;
	struct in_addr me, peer, peer_client;
	char *s, *loop, *argv[5];

	argc = 0;	
	for (s = strtok(req, " \r\n\t"); s != NULL; s = strtok(NULL, " \r\n\t")) {
		if (argc < NAAS_ARRAY_SIZE(argv)) {
			argv[argc++] = s;
		}
	}

	if (argc < 5) {
		return -EINVAL;
	}
	reqid = strtoul(argv[0], NULL, 10);
	if (naas_inet_aton(argv[1], &me, NULL)) {
		return -EINVAL;
	}
	if (naas_inet_aton(argv[2], &peer, NULL)) {
		return -EINVAL;
	}
	if (naas_inet_aton(argv[3], &peer_client, &peer_client_mask)) {
		return -EINVAL;
	}
	loop = argv[4];

	rc = route_based_updown(reqid, me, peer, peer_client, peer_client_mask, loop);

	return rc;
}

static void
handle_client(int fd)
{
	int i, rc, len;
	char req[REQBUFLEN];

	rc = read_request(fd, req, sizeof(req));
	if (rc < 0) {
		return;
	}
	len = rc;
	rc = handle_request(req);
	if (rc < 0) {
		for (i = 0; i < len; ++i) {
			if (req[i] == '\0') {
				req[i] = ' ';
			}
		}
		naas_logf(LOG_ERR, -rc, "Request '%s' failed", req);
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
	int rc, fd, lfd, dflag, Lflag, Cflag, opt, reqid,
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
			break;
		case 'h':
			print_usage();
			break;
		}
	}

	if (Lflag) {
		if (dflag) {
			daemon(0, 0);
		}
		rc = init(log_options);
		if (rc) {
			return EXIT_FAILURE;
		}
		rc = listen_onlocalport(Lflag);
		if (rc < 0) {
			deinit();
			return EXIT_FAILURE;
		}
		lfd = rc;
		while (1) {
			fd = accept(lfd, NULL, NULL);
			if (fd >= 0) {
				handle_client(fd);
				close(fd);
			}
		}
		deinit();
	} else {
		if (reqid < 0) {
			naas_print_unspecifiedarg("--reqid");
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

		if (loop == NULL) {
			naas_print_unspecifiedarg("--loop");
			print_usage();
			return EXIT_FAILURE;
		}

		if (Cflag) {
			rc = connect_tolocalport(Cflag);
			if (rc > 0) {
				fd = rc;
				rc = send_request(fd, reqid, me, peer,
					peer_client, peer_client_mask, loop);
				close(fd);
			}
		} else {
			rc = init(log_options);
			if (rc) {
				return EXIT_FAILURE;
			}

			rc = route_based_updown(reqid, me, peer,
					peer_client, peer_client_mask, loop);
	
			deinit();
		}
	}

	return rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
