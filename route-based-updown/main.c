#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

#include <libvici.h>

#include <naas-common/log.h>

struct list_sa_parser {
	int reqid;
	int found;
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
					parser->found = 1;
				}
			} else if (!strcmp(key, "spi-out")) {
				if (reqid == parser->reqid) {
					parser->spi_out = strtoul(value, NULL, 16);
					parser->found = 1;
				}
			}
			break;
		default:
			break;
		}
	}
}

static int
get_spi_inout(int reqid, int *spi_in, int *spi_out)
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

	parser.reqid = 2;
	parser.found = 0;

	rc = vici_register(conn, "list-sa", list_sa, &parser);
	if (rc != 0) {
		rc = -errno;
		naas_logf(LOG_ERR, errno, "vici_register() failed");
		goto err;
	}

	req = vici_begin("list-sas");	
	res = vici_submit(req, conn);
	if (res) {
		if (!parser.found) {
			rc = -ESRCH;
		} else {
			if (spi_in != NULL) {
				*spi_in = parser.spi_in;
			}
			if (spi_out != NULL) {
				*spi_out = parser.spi_out;
			}
		}
	} else {
		rc = -errno;
		naas_logf(LOG_ERR, errno, "vici_submit() failed");
	}

	vici_free_res(res);
err:
	vici_deinit();
	return rc;
}

int
main(int argc, char **argv)
{
	naas_log_init("route-based-updown", LOG_CONS);
	get_spi_inout(1, NULL, NULL);
	return 0;
}
