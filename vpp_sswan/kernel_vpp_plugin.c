#include <vlibmemory/api.h>

#define vl_typedefs
#define vl_endianfun
/* Include the (first) vlib-api API definition layer */
#include <vlibmemory/vl_memory_api_h.h>
/* Include the current layer (third) vpp API definition layer */
#include <vpp/api/vpe_types.api.h>
#include <vpp/api/vpe.api.h>
#undef vl_typedefs
#undef vl_endianfun

#include <vpp-api/client/stat_client.h>

#include <daemon.h>
#include <processing/jobs/callback_job.h>
#include <collections/hashtable.h>
#include <threading/mutex.h>
#include <threading/thread.h>

#include <nats/status.h>
#include <nats/nats.h>
#include <libnaas/api.h>


#if 1
#define MYDBG(...) do { \
	printf("[VAC][%s:%u] ", __FILE__, __LINE__); \
	printf(__VA_ARGS__); \
	printf("\n"); \
} while (0) 
#else
#define MYDBG(...)
#endif

struct kernel_vpp_ipsec;

typedef struct kernel_vpp_plugin_t kernel_vpp_plugin_t;

struct kernel_vpp_plugin_t {
	plugin_t plugin;
};

typedef struct kernel_vpp_listener {
	listener_t public;
	struct kernel_vpp_ipsec *ipsec;
} kernel_vpp_listener_t;

typedef struct kernel_vpp_ipsec {
	kernel_ipsec_t interface;

	refcount_t next_sad_id;
	int loop_sw_if_index;

	mutex_t *mutex;

	hashtable_t *sas;
	hashtable_t *tunnels;

	kernel_vpp_listener_t *listener;

	refcount_t nextspi;

	uint32_t mixspi;

	thread_t *keepalive;

	stat_client_main_t *sm;

	natsConnection *nats_conn;

	bool rekey_can_update_config;
	int announce_pod;
	const char *nats_server;
} kernel_vpp_ipsec_t;

typedef struct kernel_vpp_child_sa {
	uint32_t id;
	uint32_t stat_index;
	uint32_t peer_spi;
	uint32_t unique_id;
	uint32_t vrf;
} kernel_vpp_child_sa_t;

typedef struct kernel_vpp_tunnel {
	uint32_t sw_if_index;
	uint32_t vrf;
	linked_list_t *remote_ts;
} kernel_vpp_tunnel_t;

typedef struct private_kernel_vpp_plugin {
  	kernel_vpp_plugin_t public;
} private_kernel_vpp_plugin_t;

static u_int
sa_hash(kernel_ipsec_sa_id_t *sa)
{
	return chunk_hash_inc(
			sa->src->get_address (sa->src),
			chunk_hash_inc(
				sa->dst->get_address (sa->dst),
				chunk_hash_inc(chunk_from_thing (sa->spi),
					chunk_hash(chunk_from_thing(sa->proto)))));
}

static bool
sa_equals(kernel_ipsec_sa_id_t *sa, kernel_ipsec_sa_id_t *other_sa)
{
	return sa->src->ip_equals (sa->src, other_sa->src) &&
			sa->dst->ip_equals (sa->dst, other_sa->dst) &&
			sa->spi == other_sa->spi && sa->proto == other_sa->proto;
}

static u_int
permute(u_int x, u_int p)
{
	u_int qr;

	x = x % p;
	qr = ((uint64_t) x * x) % p;
	if (x <= p / 2) {
		return qr;
	}
	return p - qr;
}

static uint32_t
get_ts_addr(traffic_selector_t *ts, bool from)
{
	chunk_t chunk;
	host_t *host;
	struct sockaddr_in * addr;

	if (from) {
		chunk = ts->get_from_address(ts);
	} else {
		chunk = ts->get_to_address(ts);
	}
	host = host_create_from_chunk(AF_INET, chunk, 0);
	addr = (struct sockaddr_in *)host->get_sockaddr(host);
	return addr->sin_addr.s_addr;
}

static int
get_ts_net(traffic_selector_t *ts, struct in_addr *prefix, int *prefixlen)
{
	uint32_t from, to, num_addresses;

	if (ts->get_type(ts) != TS_IPV4_ADDR_RANGE) {
		return -EINVAL;
	}

	from = get_ts_addr(ts, true);
	to = get_ts_addr(ts, false);

	prefix->s_addr = from;

	from = ntohl(from);
	to = ntohl(to);
	if (to < from) {
		return -EINVAL;
	}
	num_addresses = to - from + 1;

	*prefixlen = 32 - __builtin_ctz(num_addresses);
	return 0;
}

static void
destroy_list_ts(linked_list_t *list_ts)
{
	list_ts->destroy_offset(list_ts, offsetof(traffic_selector_t, destroy));
}

static int
list_get_count(linked_list_t *list)
{
	return list->get_count(list);
}

static int
init_nats(kernel_vpp_ipsec_t *this)
{
	natsOptions *opts;
	natsStatus status;
	const char *servers[1];

	servers[0] = this->nats_server;
	opts = NULL;

	if (natsOptions_Create(&opts) != NATS_OK) {
		return -EINVAL;
	}

	natsOptions_SetServers(opts, servers, 1);
	status = natsConnection_Connect(&this->nats_conn, opts);
	natsOptions_Destroy(opts);
	if (status != NATS_OK) {
		return -EINVAL;
	} else {
		return 0;
	}
}

static void
nats_publish(kernel_vpp_ipsec_t *this, int is_up, uint32_t vrf, uint32_t unique_id,
		struct in_addr prefix, int prefixlen)
{
	const char *subj;
	char buf[128];
	int len;
	
	len = snprintf(buf, sizeof(buf), "%u %u %u %s/%u", this->announce_pod, vrf, unique_id,
			inet_ntoa(prefix), prefixlen);

	if (is_up) {
		subj = "tunnel-up";
	} else {
		subj = "tunnel-down";
	}

	natsConnection_Publish(this->nats_conn, subj, buf, len);
}

// Initialize seeds for SPI generation
static int
init_spi(kernel_vpp_ipsec_t *this)
{
	rng_t *rng;
	bool ok;

	rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (!rng) {
		return -EINVAL;
	}
	ok = rng->get_bytes(rng, sizeof (this->nextspi), (uint8_t *)&this->nextspi);
	if (ok) {
		ok = rng->get_bytes(rng, sizeof (this->mixspi), (uint8_t *)&this->mixspi);
	}
	rng->destroy(rng);
	return ok ? 0 : -EINVAL;
}

static uint32_t
get_other_id(ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	u_char c;
	int i;
	uint32_t id;
	identification_t* peer_id;
	host_t *src, *dst;
	id_type_t peer_id_type;
	chunk_t chunk;

	peer_id = ike_sa->get_other_id(ike_sa);
	peer_id_type = peer_id->get_type(peer_id);
	if (peer_id_type != ID_KEY_ID) {
		goto err;
	}

	chunk = peer_id->get_encoding(peer_id);
	if (chunk.len < 1 || chunk.len > 4) {
		goto err;
	}

	// TODO: Find implementation of this algorithm in strongswan and call api
	id = 0;
	for (i = 0; i < chunk.len; ++i) {
		id *= 10;
		c = chunk.ptr[i];
		if (c < '0' || c > '9') {
			goto err;
		}
		id += c - '0';
	}

	return id;

err:
	src = ike_sa->get_my_host(ike_sa);
	dst = ike_sa->get_other_host(ike_sa);
	DBG1(DBG_KNL, "SA_CHILD %#H == %#H with SPI %.8x has invalid peerid type %d",
			src, dst, child_sa->get_spi(child_sa, TRUE) ,peer_id_type);
	return ~0;
}

static uint32_t
create_ipsec_interface(kernel_vpp_ipsec_t *this, uint32_t unique_id)
{
	uint32_t sw_if_index;

	naas_api_ipsec_itf_create(unique_id, &sw_if_index);
	naas_api_sw_interface_set_unnumbered(1, this->loop_sw_if_index,	sw_if_index);
	naas_api_sw_interface_set_flags(sw_if_index, IF_STATUS_API_FLAG_ADMIN_UP);
	return sw_if_index;
}

METHOD (kernel_ipsec_t, ipsec_get_features, kernel_feature_t, kernel_vpp_ipsec_t *this)
{
	return KERNEL_ESP_V3_TFC;
}

METHOD (kernel_ipsec_t, get_spi, status_t, kernel_vpp_ipsec_t *this,
		host_t *src, host_t *dst, uint8_t protocol, uint32_t *spi)
{
	static const u_int p = 268435399;
	static const u_int offset = 0xc0000000;

	*spi = htonl (offset + permute (ref_get (&this->nextspi) ^ this->mixspi, p));
	return SUCCESS;
}

METHOD (kernel_ipsec_t, get_cpi, status_t, kernel_vpp_ipsec_t *this,
		host_t *src, host_t *dst, uint16_t *cpi)
{
	DBG1(DBG_KNL, "get_cpi is not supported!!!!!!!!!!!!!!!!!!!!!!!!");
	return NOT_SUPPORTED;
}

typedef struct {
	kernel_vpp_ipsec_t *manager;
	kernel_ipsec_sa_id_t *sa_id;
	// 0 if this is a hard expire, otherwise the offset in s (soft->hard)
	uint32_t hard_offset;
} vpp_sa_expired_t;

static void
expire_data_destroy(vpp_sa_expired_t *data)
{
	free(data);
}

static job_requeue_t
sa_expired(vpp_sa_expired_t *expired)
{
	kernel_vpp_ipsec_t *this = expired->manager;
	kernel_vpp_child_sa_t *sa;
	kernel_ipsec_sa_id_t *id;

	this = expired->manager;
	id = expired->sa_id;

	this->mutex->lock(this->mutex);
	sa = this->sas->get(this->sas, id);

	if (sa) {
		charon->kernel->expire(charon->kernel, id->proto, id->spi, id->dst, FALSE);
	}

	if (id->src) {
		id->src->destroy (id->src);
	}
	if (id->dst) {
		id->dst->destroy (id->dst);
	}
	free(id);

	this->mutex->unlock(this->mutex);
	return JOB_REQUEUE_NONE;
}


// Schedule a job to handle IPsec SA expiration
static void
schedule_expiration(kernel_vpp_ipsec_t *this, lifetime_cfg_t *lifetime,
		kernel_ipsec_sa_id_t *entry2)
{
	vpp_sa_expired_t *expired;
	callback_job_t *job;
	uint32_t timeout;
	kernel_ipsec_sa_id_t *id;

	if (!lifetime->time.life) { 
		// no expiration at all
		return;
	}

	INIT(id,
		.src = entry2->src->clone(entry2->src),
		.dst = entry2->dst->clone(entry2->dst),
		.spi = entry2->spi,
		.proto = entry2->proto,
	);

	INIT(expired,
		.manager = this,
		.sa_id = id,
	);

	// schedule a rekey first, a hard timeout will be scheduled then, if any
	expired->hard_offset = lifetime->time.life - lifetime->time.rekey;
	timeout = lifetime->time.rekey;

	if (lifetime->time.life <= lifetime->time.rekey || lifetime->time.rekey == 0) {
		// no rekey, schedule hard timeout
		expired->hard_offset = 0;
		timeout = lifetime->time.life;
	}

	job = callback_job_create((callback_job_cb_t)sa_expired, expired,
		(callback_job_cleanup_t)expire_data_destroy, NULL);
	lib->scheduler->schedule_job (lib->scheduler, (job_t *) job, timeout);
}

static kernel_vpp_child_sa_t *
kernel_vpp_sa_create(kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id)
{
	kernel_vpp_child_sa_t *sa;
	kernel_ipsec_sa_id_t *key;

	INIT(key,
		.src = id->src->clone(id->src),
		.dst = id->dst->clone(id->dst),
		.spi = id->spi,
		.proto = id->proto,
	);

	INIT(sa,
		.id = ~0,
		.stat_index = ~0,
		.peer_spi = ~0,
		.unique_id = ~0,
	);

	DBG1(DBG_KNL, "put SA_CHILD %#H == %#H with SPI %.8x",
			key->src, key->dst, htonl(key->spi));
	this->sas->put(this->sas, key, sa);

	return sa;
}

METHOD(kernel_ipsec_t, add_sa, status_t, kernel_vpp_ipsec_t *this,
		kernel_ipsec_sa_id_t *id, kernel_ipsec_add_sa_t *data)
{
	naas_err_t err;
	vl_api_ipsec_sad_entry_add_del_t mp;
	vl_api_ipsec_sad_entry_add_del_reply_t *rmp;
	uint8_t ca, ia;
	uint32_t sad_id, stat_index;
	chunk_t src, dst;
	kernel_ipsec_sa_id_t key;
	kernel_vpp_child_sa_t *sa;
	int key_len;

	ca = ia = 0;
	key_len = data->enc_key.len;
	sad_id = ref_get(&this->next_sad_id); 

	if ((data->enc_alg == ENCR_AES_CTR) || (data->enc_alg == ENCR_AES_GCM_ICV8) ||
		(data->enc_alg == ENCR_AES_GCM_ICV12) || (data->enc_alg == ENCR_AES_GCM_ICV16)) {
		// See how enc_size is calculated at keymat_v2.derive_child_keys
		static const int SALT_SIZE = 4; 
		key_len = key_len - SALT_SIZE;
	}
	memset(&mp, 0, sizeof (mp));
	u16 msg_id =  vl_msg_api_get_msg_index ((u8 *) "ipsec_sad_entry_add_del_ab64b5c6");
	mp._vl_msg_id = htons (msg_id);
	mp.is_add = 1;
	mp.entry.sad_id = htonl (sad_id);
	mp.entry.spi = id->spi;
	mp.entry.protocol = id->proto == IPPROTO_ESP ? htonl (IPSEC_API_PROTO_ESP) :
			htonl (IPSEC_API_PROTO_AH);

	switch (data->enc_alg) {
	case ENCR_NULL:
		ca = IPSEC_API_CRYPTO_ALG_NONE;
		break;
	case ENCR_AES_CBC:
		switch (key_len * 8) {
		case 128:
			ca = IPSEC_API_CRYPTO_ALG_AES_CBC_128;
			break;
		case 192:
			ca = IPSEC_API_CRYPTO_ALG_AES_CBC_192;
			break;
		case 256:
			ca = IPSEC_API_CRYPTO_ALG_AES_CBC_256;
			break;
		default:
			DBG1(DBG_KNL, "Key length %d is not supported by VPP!", key_len * 8);
			return FAILED;
		}
		break;
	case ENCR_AES_CTR:
		switch (key_len * 8) {
		case 128:
			ca = IPSEC_API_CRYPTO_ALG_AES_CTR_128;
			break;
		case 192:
			ca = IPSEC_API_CRYPTO_ALG_AES_CTR_192;
			break;
		case 256:
			ca = IPSEC_API_CRYPTO_ALG_AES_CTR_256;
			break;
		default:
			DBG1(DBG_KNL, "Key length %d is not supported by VPP!", key_len * 8);
			return FAILED;
		}
		break;
	case ENCR_AES_GCM_ICV8:
	case ENCR_AES_GCM_ICV12:
	case ENCR_AES_GCM_ICV16:
		switch (key_len * 8) {
		case 128:
			ca = IPSEC_API_CRYPTO_ALG_AES_GCM_128;
			break;
		case 192:
			ca = IPSEC_API_CRYPTO_ALG_AES_GCM_192;
			break;
		case 256:
			ca = IPSEC_API_CRYPTO_ALG_AES_GCM_256;
			break;
		default:
			DBG1 (DBG_KNL, "Key length %d is not supported by VPP!", key_len * 8);
			return FAILED;
		}
		break;
	case ENCR_DES:
		ca = IPSEC_API_CRYPTO_ALG_DES_CBC;
		break;
	case ENCR_3DES:
		ca = IPSEC_API_CRYPTO_ALG_3DES_CBC;
		break;
	default:
		DBG1(DBG_KNL, "algorithm %N not supported by VPP!",
				encryption_algorithm_names, data->enc_alg);
		return FAILED;
	}
	mp.entry.crypto_algorithm = htonl(ca);
	mp.entry.crypto_key.length = key_len < 128 ? key_len : 128;
	memcpy (mp.entry.crypto_key.data, data->enc_key.ptr, mp.entry.crypto_key.length);

	// copy salt for AEAD algorithms
	if ((data->enc_alg == ENCR_AES_CTR) ||
			(data->enc_alg == ENCR_AES_GCM_ICV8) ||
			(data->enc_alg == ENCR_AES_GCM_ICV12) ||
			(data->enc_alg == ENCR_AES_GCM_ICV16)) {
		memcpy (&mp.entry.salt, data->enc_key.ptr + mp.entry.crypto_key.length, 4);
	}

	switch (data->int_alg) {
		case AUTH_UNDEFINED:
		ia = IPSEC_API_INTEG_ALG_NONE;
		break;
	case AUTH_HMAC_MD5_96:
		ia = IPSEC_API_INTEG_ALG_MD5_96;
		break;
	case AUTH_HMAC_SHA1_96:
		ia = IPSEC_API_INTEG_ALG_SHA1_96;
		break;
	case AUTH_HMAC_SHA2_256_96:
		ia = IPSEC_API_INTEG_ALG_SHA_256_96;
		break;
	case AUTH_HMAC_SHA2_256_128:
		ia = IPSEC_API_INTEG_ALG_SHA_256_128;
		break;
	case AUTH_HMAC_SHA2_384_192:
		ia = IPSEC_API_INTEG_ALG_SHA_384_192;
		break;
	case AUTH_HMAC_SHA2_512_256:
		ia = IPSEC_API_INTEG_ALG_SHA_512_256;
		break;
	default:
		DBG1 (DBG_KNL, "algorithm %N not supported by VPP!",
				integrity_algorithm_names, data->int_alg);
		return FAILED;
	}

	mp.entry.integrity_algorithm = htonl (ia);
	mp.entry.integrity_key.length = data->int_key.len < 128 ? data->int_key.len : 128;
	memcpy(mp.entry.integrity_key.data,
			data->int_key.ptr, mp.entry.integrity_key.length);

	int flags = IPSEC_API_SAD_FLAG_NONE;
	if (data->inbound)
		flags |= IPSEC_API_SAD_FLAG_IS_INBOUND;
	// like the kernel-netlink plugin, anti-replay can be disabled with zero
	// replay_window, but window size cannot be customized for vpp
	if (data->replay_window)
		flags |= IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY;
	if (data->esn)
		flags |= IPSEC_API_SAD_FLAG_USE_ESN;

	if (data->mode == MODE_TUNNEL) {
		if (id->src->get_family (id->src) == AF_INET6) {
			flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL_V6;
		} else {
			flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL;
		}
    	}
	if (data->encap) {
		flags |= IPSEC_API_SAD_FLAG_UDP_ENCAP;
		if (id->src->get_family(id->src) != AF_INET ||
				id->dst->get_family(id->dst) != AF_INET) {
			DBG1 (DBG_KNL, "UDP encap not IPv4");
		} else {
			struct sockaddr_in *src_sockaddr;
			struct sockaddr_in *dst_sockaddr;

			src_sockaddr = (struct sockaddr_in *)id->src->get_sockaddr(id->src);
			dst_sockaddr = (struct sockaddr_in *)id->dst->get_sockaddr(id->dst);

			mp.entry.udp_src_port = src_sockaddr->sin_port;
			mp.entry.udp_dst_port = dst_sockaddr->sin_port;
		}

	}
	mp.entry.flags = htonl(flags);

	bool is_ipv6 = false;
	if (id->src->get_family (id->src) == AF_INET6) {
		is_ipv6 = true;
		mp.entry.tunnel_src.af = htonl (ADDRESS_IP6);
		mp.entry.tunnel_dst.af = htonl (ADDRESS_IP6);
	} else {
		mp.entry.tunnel_src.af = htonl (ADDRESS_IP4);
		mp.entry.tunnel_dst.af = htonl (ADDRESS_IP4);
	}
	src = id->src->get_address (id->src);
	memcpy (is_ipv6 ? mp.entry.tunnel_src.un.ip6 : mp.entry.tunnel_src.un.ip4,
			src.ptr, src.len);
	dst = id->dst->get_address (id->dst);
	memcpy (is_ipv6 ? mp.entry.tunnel_dst.un.ip6 : mp.entry.tunnel_dst.un.ip4,
			dst.ptr, dst.len);

	this->mutex->lock(this->mutex);
	err = NAAS_API_INVOKE(mp, rmp);
	if (rmp) {
		stat_index = ntohl(rmp->stat_index);
	}
	naas_api_msg_free(rmp);
	if (err.num && err.type == NAAS_ERR_ERRNO) {
		DBG1(DBG_KNL, "vac adding SA with SPI %.8x failed", htonl(id->spi));
		goto err;
	}
	if (err.num && err.type == NAAS_ERR_VNET) {
		DBG1(DBG_KNL, "add SA failed rv:%d", err.num);
		goto err;
	}

	key.src = id->src;
	key.dst = id->dst;
	key.spi = id->spi;
	key.proto = id->proto;

	sa = this->sas->get(this->sas, &key);
	if (sa == NULL) {
		sa = kernel_vpp_sa_create(this, &key);
		sa->id = sad_id;
	}

	sa->stat_index = stat_index;

	schedule_expiration(this, data->lifetime, id);
	this->mutex->unlock(this->mutex);

	return SUCCESS;

err:
	this->mutex->unlock(this->mutex);
	return FAILED;
}

METHOD(kernel_ipsec_t, query_sa, status_t, kernel_vpp_ipsec_t *this,
		kernel_ipsec_sa_id_t *id, kernel_ipsec_query_sa_t *data,
	uint64_t *bytes, uint64_t *packets, time_t *time)
{
	kernel_vpp_child_sa_t *sa;
	u32 *dir;
	int i, k, rv_stat;
	stat_segment_data_t *res;
	u8 **pattern;
	uint64_t res_bytes;
	uint64_t res_packets;

	dir = NULL;
	res = NULL;
	pattern = NULL;
	res_bytes = 0;
	res_packets = 0;

	this->mutex->lock(this->mutex);
	sa = this->sas->get(this->sas, id);
	if (!sa) {
		DBG1 (DBG_KNL, "CHILD_SA withs SPI %.8x not found", htonl(id->spi));
		this->mutex->unlock (this->mutex);
		return NOT_FOUND;
	}

	if (this->sm == NULL) {
		stat_client_main_t *sm = NULL;
		sm = stat_client_get ();

		if (!sm) {
			DBG1(DBG_KNL, "Not connecting with stats segmentation");
			this->mutex->unlock(this->mutex);
			return NOT_FOUND;
		}
		this->sm = sm;
		rv_stat = stat_segment_connect_r("/run/vpp/stats.sock", this->sm);
		if (rv_stat != 0) {
			stat_client_free(this->sm);
			this->sm = NULL;
			DBG1(DBG_KNL, "Not connecting with stats segmentation");
			this->mutex->unlock (this->mutex);
			return NOT_FOUND;
		}
	}

	vec_add1 (pattern, (u8 *) "/net/ipsec/sa");
	dir = stat_segment_ls_r ((u8 **) pattern, this->sm);
	res = stat_segment_dump_r (dir, this->sm);
 	// i-loop for each results find by pattern - here two:
	// 1. /net/ipsec/sa
	// 2. /net/ipsec/sa/lost
	for (i = 0; i < vec_len (res); i++) {
		switch (res[i].type) {
		// type for how many packets are lost
		case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
			if (res[i].simple_counter_vec == 0) {
				continue;
			}
			break;
		// type for counter for each SA
		case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
			if (res[i].combined_counter_vec == 0) {
				continue;
			}
			// k-loop for each threads - that you run VPP
			for (k = 0; k < vec_len (res[i].combined_counter_vec); k++) {
				if (sa->stat_index <= vec_len (res[i].combined_counter_vec[k])) {
					DBG1(DBG_KNL, "Thread: %d, Packets: %lu, Bytes: %lu", k,
						res[i].combined_counter_vec[k][sa->stat_index].packets,
						res[i].combined_counter_vec[k][sa->stat_index].bytes);
					res_bytes += res[i].combined_counter_vec[k][sa->stat_index].bytes;
					res_packets += res[i].combined_counter_vec[k][sa->stat_index].packets;
				}
			}
			break;
		case STAT_DIR_TYPE_NAME_VECTOR:
			if (res[i].name_vector == 0)
				continue;
			break;
		default:
			break;
		}
	}

	vec_free(pattern);
	vec_free(dir);
	stat_segment_data_free(res);

	if (bytes) {
		*bytes = res_bytes;
	}
	if (packets) {
		*packets = res_packets;
	}
	if (time) {
		*time = 0;
	}

	this->mutex->unlock (this->mutex);
	return SUCCESS;
}

status_t
kernel_vpp_del_sa(kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id)
{
	naas_err_t err;
	vl_api_ipsec_sad_entry_add_del_t mp;
	vl_api_ipsec_sad_entry_add_del_reply_t *rmp;
	status_t rv;
	kernel_vpp_child_sa_t *sa;

	rv = FAILED;

	this->mutex->lock (this->mutex);
	sa = this->sas->get(this->sas, id);
	if (!sa) {
		DBG1 (DBG_KNL, "SA_CHILD with SPI %.8x not found", htonl(id->spi));
		rv = NOT_FOUND;
		goto error;
	}
	memset (&mp, 0, sizeof (mp));
	mp.is_add = 0;
	u16 msg_id = vl_msg_api_get_msg_index((u8 *) "ipsec_sad_entry_add_del_ab64b5c6");
	mp._vl_msg_id = htons (msg_id);
	mp.entry.sad_id = htonl(sa->id);

  	err = NAAS_API_INVOKE(mp, rmp);
	naas_api_msg_free(rmp);
	if (err.num && err.type == NAAS_ERR_ERRNO) {
		DBG1(DBG_KNL, "removing SA_CHILD with SPI %.8x failed", htonl(id->spi));
		goto error;
	}
	if (err.num && err.type == NAAS_ERR_VNET) {
		DBG1(DBG_KNL, "del SA_CHILD with SPI %.8x failed rv:%d", htonl(id->spi), err.num);
		goto error;
	}

	this->sas->remove(this->sas, id);
	free(sa);
	rv = SUCCESS;

error:
	this->mutex->unlock(this->mutex);
	return rv;
}

METHOD(kernel_ipsec_t, del_sa, status_t, kernel_vpp_ipsec_t *this,
		kernel_ipsec_sa_id_t *id, kernel_ipsec_del_sa_t *data)
{
	return kernel_vpp_del_sa(this, id);
}

METHOD(kernel_ipsec_t, update_sa, status_t, kernel_vpp_ipsec_t *this,
		kernel_ipsec_sa_id_t *id, kernel_ipsec_update_sa_t *data)
{
	DBG1(DBG_KNL, "update SA_CHILD %#H == %#H with SPI %.8x to %#H == %#H not supported",
			id->src, id->dst, htonl(id->spi),
			data->new_src, data->new_dst);

	return NOT_SUPPORTED;
}

METHOD (kernel_ipsec_t, flush_sas, status_t, kernel_vpp_ipsec_t *this)
{
	enumerator_t *enumerator;
	vl_api_ipsec_sad_entry_add_del_t mp;
	vl_api_ipsec_sad_entry_add_del_reply_t *rmp;
	kernel_vpp_child_sa_t *sa = NULL;
	status_t rv = FAILED;
	naas_err_t err;

	this->mutex->lock(this->mutex);
	enumerator = this->sas->create_enumerator (this->sas);
	while (enumerator->enumerate(enumerator, &sa)) {
		memset(&mp, 0, sizeof(mp));
		u16 msg_id = vl_msg_api_get_msg_index ((u8 *) "ipsec_sad_entry_add_del_ab64b5c6");
		mp._vl_msg_id = htons (msg_id);
		mp.entry.sad_id = htonl (sa->id);
		mp.is_add = 0;
		err = NAAS_API_INVOKE(mp, rmp);
		naas_api_msg_free(rmp);
		if (err.num) {
			if (err.type == NAAS_ERR_ERRNO) {
				DBG1(DBG_KNL, "flush_sas failed!!!!");
			} else {
				DBG1(DBG_KNL, "flush_sas failed!!!! rv: %d", err.num);
			}
			rv = FAILED;
			goto error;
		}
		this->sas->remove_at (this->sas, enumerator);
		free(sa);
	}
	rv = SUCCESS;
error:
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	return rv;
}

METHOD(kernel_ipsec_t, add_policy, status_t, kernel_vpp_ipsec_t *this,
		kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
		kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
		kernel_ipsec_query_policy_t *data, time_t *use_time)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_policy, status_t, kernel_vpp_ipsec_t *this,
		kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_policies, status_t, kernel_vpp_ipsec_t *this)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, bypass_socket, bool, kernel_vpp_ipsec_t *this, int fd, int family)
{
	return FALSE;
}

METHOD (kernel_ipsec_t, enable_udp_decap, bool,
		kernel_vpp_ipsec_t *this, int fd, int family, u_int16_t port)
{
	return TRUE;
}

METHOD(kernel_ipsec_t, ipsec_destroy, void, kernel_vpp_ipsec_t *this)
{
	if (this->nats_conn != NULL) {
		natsConnection_Destroy(this->nats_conn);
		nats_Close();
	}
	if (this->listener != NULL) {
		charon->bus->remove_listener(charon->bus, &this->listener->public);
		free(this->listener);
	}
	this->keepalive->cancel(this->keepalive);
	this->mutex->destroy(this->mutex);
	this->sas->destroy(this->sas);
	this->tunnels->destroy(this->tunnels);
	if (this->sm) {
		stat_segment_disconnect_r(this->sm);
		stat_client_free (this->sm);
		this->sm = NULL;
	}
	free(this);
}

static void *
keepalive_fn(kernel_vpp_ipsec_t *this)
{
	vl_api_show_version_reply_t ver;

	while (1) {
		this->mutex->lock (this->mutex);
		naas_api_show_version(&ver);
		this->mutex->unlock (this->mutex);
		sleep(2);
	}
	return NULL;
}

METHOD(listener_t, ike_updown, bool, kernel_vpp_listener_t *this, ike_sa_t *ike_sa, bool up) 
{
	MYDBG("ike_%s", up ? "up" : "down");
	return TRUE;
}

METHOD(listener_t, child_state_change, bool,
	kernel_vpp_listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
	child_sa_state_t state)
{
	return TRUE;
}

static void
update_routes(struct kernel_vpp_ipsec *ipsec, int is_add, uint32_t sw_if_index,
		uint32_t vrf, uint32_t unique_id, linked_list_t *remote_ts)
{
	int prefixlen;
	struct in_addr prefix;
	enumerator_t *e;
	traffic_selector_t *ts;

	e = remote_ts->create_enumerator(remote_ts);
	while (e->enumerate(e, &ts)) {
		get_ts_net(ts, &prefix, &prefixlen);
		naas_api_ip_route_add_del(is_add, vrf, prefix, prefixlen, sw_if_index);
		nats_publish(ipsec, is_add, vrf, unique_id, prefix, prefixlen);
	}
	e->destroy(e);
}

static void
tunnel_update_remote_ts(struct kernel_vpp_ipsec *ipsec, kernel_vpp_tunnel_t *tunnel,
		uint32_t vrf, uint32_t unique_id, linked_list_t *remote_ts_new)
{
	bool found;
	linked_list_t *remote_ts_old, *remote_ts_add;
	enumerator_t *e_old, *e_new;
	traffic_selector_t *ts_old, *ts_new;

	remote_ts_old = tunnel->remote_ts;
	tunnel->remote_ts = remote_ts_new;

	remote_ts_add = linked_list_create();

	e_new = remote_ts_new->create_enumerator(remote_ts_new);
	e_old = remote_ts_old->create_enumerator(remote_ts_old);

//	MYDBG("set_remote_ts");
	while (e_new->enumerate(e_new, &ts_new)) {
//		struct in_addr prefix;
//		int prefixlen;
//		get_ts_net(ts_new, &prefix, &prefixlen);
//		MYDBG("%s/%d", inet_ntoa(prefix), prefixlen);

		found = false;
		while (e_old->enumerate(e_old, &ts_old)) {
			if (ts_old->equals(ts_old, ts_new)) {
				remote_ts_old->remove_at(remote_ts_old, e_old);
				found = true;
				break;
			}
		}
		if (!found) {
			remote_ts_add->insert_last(remote_ts_add, ts_new);
		}
		remote_ts_old->reset_enumerator(remote_ts_old, e_old);
	}
	e_new->destroy(e_new);
	e_old->destroy(e_old);

	if (list_get_count(remote_ts_add) || list_get_count(remote_ts_old)) {
		update_routes(ipsec, 1, tunnel->sw_if_index, vrf, unique_id, remote_ts_add);
		update_routes(ipsec, 0, tunnel->sw_if_index, vrf, unique_id, remote_ts_old);
	}

	destroy_list_ts(remote_ts_old);
	remote_ts_add->destroy(remote_ts_add);
}

static void
tunnel_set_remote_ts(struct kernel_vpp_ipsec *ipsec, kernel_vpp_tunnel_t *tunnel,
		uint32_t vrf, uint32_t unique_id, linked_list_t *remote_ts_new)
{
	tunnel->remote_ts = remote_ts_new;
	update_routes(ipsec, 1, tunnel->sw_if_index, vrf, unique_id, tunnel->remote_ts);
}

static void
kernel_vpp_child_down(kernel_vpp_listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	uint32_t vrf;
	uintptr_t unique_id;
	kernel_vpp_tunnel_t *tunnel;

	unique_id = ike_sa->get_unique_id(ike_sa);
	tunnel = this->ipsec->tunnels->get(this->ipsec->tunnels, (void *)unique_id);
	if (tunnel == NULL) {
		return;
	}
	vrf = tunnel->vrf;
	this->ipsec->tunnels->remove(this->ipsec->tunnels, (void *)unique_id);

	update_routes(this->ipsec, 0, tunnel->sw_if_index, vrf, unique_id, tunnel->remote_ts);
	tunnel->remote_ts->destroy_offset(tunnel->remote_ts,
			offsetof(traffic_selector_t, destroy));
	naas_api_ipsec_itf_delete(tunnel->sw_if_index);
	free(tunnel);
}

static	linked_list_t *
get_traffic_selectors(child_sa_t *child_sa, bool is_local)
{
	child_cfg_t* cfg;

	cfg = child_sa->get_config(child_sa);
	return cfg->get_traffic_selectors(cfg, is_local, NULL, NULL, false);
}

static void
kernel_vpp_child_up(kernel_vpp_listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	uint32_t sw_if_index, i_spi, o_spi, vrf;
	uintptr_t unique_id;
	protocol_id_t proto;
	linked_list_t *remote_ts;
	kernel_vpp_tunnel_t *tunnel;
	kernel_ipsec_sa_id_t o_key, i_key;
	kernel_vpp_child_sa_t *i_sa, *o_sa;

	vrf = get_other_id(ike_sa, child_sa);
	if (vrf == ~0) {
		return;
	}

	proto = child_sa->get_protocol(child_sa);

	unique_id = ike_sa->get_unique_id(ike_sa);

	o_key.src = ike_sa->get_my_host(ike_sa);
	o_key.dst = ike_sa->get_other_host(ike_sa);
	o_key.proto = proto == PROTO_ESP ? IPPROTO_ESP : IPPROTO_AH;
	o_spi = child_sa->get_spi(child_sa, FALSE);
	o_key.spi = o_spi;
	o_sa = this->ipsec->sas->get(this->ipsec->sas, &o_key);

	i_key.src = ike_sa->get_other_host(ike_sa);
	i_key.dst = ike_sa->get_my_host(ike_sa);
	i_key.proto = proto == PROTO_ESP ? IPPROTO_ESP : IPPROTO_AH;
	i_spi = child_sa->get_spi(child_sa, TRUE);
	i_key.spi = i_spi;
	i_sa = this->ipsec->sas->get(this->ipsec->sas, &i_key);

	unique_id = ike_sa->get_unique_id(ike_sa);
	tunnel = this->ipsec->tunnels->get(this->ipsec->tunnels, (void *)unique_id);
	if (tunnel == NULL) {
		sw_if_index = create_ipsec_interface(this->ipsec, unique_id);
		if (sw_if_index == ~0) {
			return;
		}
		INIT(tunnel);
		tunnel->sw_if_index = sw_if_index;
		tunnel->remote_ts = NULL;
		tunnel->vrf = vrf;
		this->ipsec->tunnels->put(this->ipsec->tunnels, (void *)unique_id, tunnel);
	} else {
		sw_if_index = tunnel->sw_if_index;
	}

	if (o_sa != NULL && i_sa != NULL) {
		naas_api_ipsec_tunnel_protect_update(sw_if_index, i_sa->id, o_sa->id);
	} else {
		if (o_sa == NULL) {
			o_sa = kernel_vpp_sa_create(this->ipsec, &o_key);
		}
		if (i_sa == NULL) {
			i_sa = kernel_vpp_sa_create(this->ipsec, &i_key);
		}
		
		o_sa->unique_id = i_sa->unique_id = unique_id;
		o_sa->peer_spi = i_spi;
		i_sa->peer_spi = o_spi;
	}

	if (tunnel->remote_ts == NULL) {
		remote_ts = get_traffic_selectors(child_sa, false);
		tunnel_set_remote_ts(this->ipsec, tunnel, vrf, unique_id, remote_ts);
	} else if (this->ipsec->rekey_can_update_config) {
		remote_ts = get_traffic_selectors(child_sa, false);
		tunnel_update_remote_ts(this->ipsec, tunnel, vrf, unique_id, remote_ts);
	}
}

METHOD(listener_t, child_updown, bool,
		kernel_vpp_listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa, bool up)
{
	uint32_t i_spi, o_spi;

	i_spi = child_sa->get_spi(child_sa, TRUE);
	o_spi = child_sa->get_spi(child_sa, FALSE);

	MYDBG("child_%s %.8x_i %.8x_o", up ? "up" : "down", ntohl(i_spi), ntohl(o_spi));

	this->ipsec->mutex->lock(this->ipsec->mutex);
	if (up) {
		kernel_vpp_child_up(this, ike_sa, child_sa);
	} else {
		kernel_vpp_child_down(this, ike_sa, child_sa);
	}
	this->ipsec->mutex->unlock(this->ipsec->mutex);

	return TRUE;
}

METHOD(listener_t, child_rekey, bool,
		kernel_vpp_listener_t *this, ike_sa_t *ike_sa, child_sa_t *old, child_sa_t *new)
{
	uint32_t new_i_spi, new_o_spi, old_i_spi, old_o_spi;

	new_i_spi = new->get_spi(new, TRUE);
	new_o_spi = new->get_spi(new, FALSE);
	old_i_spi = old->get_spi(old, TRUE);
	old_o_spi = old->get_spi(old, FALSE);

	MYDBG("child_rekey %.8x_i %.8x_o => %.8x_i %.8x_o",
			ntohl(old_i_spi), ntohl(old_o_spi), ntohl(new_i_spi), ntohl(new_o_spi));

	this->ipsec->mutex->lock(this->ipsec->mutex);
	kernel_vpp_child_up(this, ike_sa, new);
	this->ipsec->mutex->unlock(this->ipsec->mutex);

	return TRUE;
}

kernel_vpp_listener_t *
kernel_vpp_listener_create(kernel_vpp_ipsec_t *ipsec)
{
	kernel_vpp_listener_t *this;

	INIT(this,
		.public = {
			.ike_updown = _ike_updown,
			.child_state_change = _child_state_change,
			.child_updown = _child_updown,
			.child_rekey = _child_rekey,
		},
		.ipsec = ipsec,
	);

	return this;
}

kernel_vpp_ipsec_t *
kernel_vpp_ipsec_create()
{
	uint32_t sw_if_index;
	kernel_vpp_ipsec_t *this;

	naas_api_create_loopback(&sw_if_index);

	INIT(this,
		.interface = {
			.get_features = _ipsec_get_features,
			.get_spi = _get_spi,
			.get_cpi = _get_cpi,
			.add_sa  = _add_sa,
			.update_sa = _update_sa,
			.query_sa = _query_sa,
			.del_sa = _del_sa,
			.flush_sas = _flush_sas,
			.add_policy = _add_policy,
			.query_policy = _query_policy,
			.del_policy = _del_policy,
			.flush_policies = _flush_policies,
			.bypass_socket = _bypass_socket,
			.enable_udp_decap = _enable_udp_decap,
			.destroy = _ipsec_destroy,
		},
		.next_sad_id = 0,
		.loop_sw_if_index = sw_if_index,
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.sas = hashtable_create((hashtable_hash_t)sa_hash,
					(hashtable_equals_t)sa_equals, 32),
		.tunnels = hashtable_create(hashtable_hash_ptr, hashtable_equals_ptr, 4),
		.sm = NULL,
		.rekey_can_update_config = lib->settings->get_bool(lib->settings,
			"%s.plugins.kernel-vpp.rekey_can_update_config", false, lib->ns),
		.announce_pod = lib->settings->get_int(lib->settings,
			"%s.plugins.kernel-vpp.announce_pod", 0, lib->ns),
		.nats_server = lib->settings->get_str(lib->settings,
			"%s.plugins.kernel-vpp.nats_server", "localhost", lib->ns),
	);

	this->listener = NULL;
	this->nats_conn = NULL;
	this->keepalive = thread_create((thread_main_t)keepalive_fn, this);

	if (init_spi(this)) {
		DBG1(DBG_KNL, "failed to initialize spis");
		ipsec_destroy(this);
		return NULL;
	}

	if (init_nats(this)) {
		DBG1(DBG_KNL, "connection to nats failed");
		ipsec_destroy(this);
		return NULL;
	}

	this->listener = kernel_vpp_listener_create(this);
	charon->bus->add_listener(charon->bus, &this->listener->public);

	DBG1(DBG_KNL, "kernel-vpp initialized");

	return this;
}

METHOD(plugin_t, get_name, char *, private_kernel_vpp_plugin_t *this)
{
	return "kernel-vpp";
}

METHOD(plugin_t, get_features, int, private_kernel_vpp_plugin_t *this,
		plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(kernel_ipsec_register, kernel_vpp_ipsec_create),
		PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, plugin_destroy, void, private_kernel_vpp_plugin_t *this)
{
	free(this);
}

plugin_t *
kernel_vpp_plugin_create()
{
	int rc;
	private_kernel_vpp_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _plugin_destroy,
			},
		},
	);

	rc = naas_api_init("strongswan");
 	if (rc) {
		DBG1(DBG_KNL, "connection to vpp failed");
		plugin_destroy(this);
		return NULL;
	}

	return &this->public.plugin;
}
