/*
 * Copyright (c) 2022 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <utils/debug.h>
#include <vlibapi/api.h>
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

#include "kernel_vpp_plugin.h"
#include "kernel_vpp_shared.h"

#include <libnaas/api.h>

#include <daemon.h>

//=====================================================================

#include <vnet/ipsec/ipsec.h>
#include <vnet/vnet.h>
#include <collections/hashtable.h>
#include <threading/mutex.h>
#include <threading/thread.h>

#include <processing/jobs/callback_job.h>
#include <vpp-api/client/stat_client.h>

#define vl_typedefs
#define vl_endianfun
/* Include the (first) vlib-api API definition layer */
#include <vlibmemory/vl_memory_api_h.h>
/* Include the current layer (third) vpp API definition layer */
#include <vpp/api/vpe_types.api.h>
#include <vpp/api/vpe.api.h>

#include <vnet/ip-neighbor/ip_neighbor.api_enum.h>
#include <vnet/ip-neighbor/ip_neighbor.api_types.h>
#include <vnet/ipsec/ipsec.api_enum.h>
#include <vnet/ipsec/ipsec.api_types.h>
#include <vnet/interface.api_enum.h>
#include <vnet/interface.api_types.h>
#undef vl_typedefs
#undef vl_endianfun

#include "kernel_vpp_shared.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/route.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <net/if_arp.h>
#include <sys/stat.h>
#include <dirent.h>

#include <libnaas/api.h>


u32 natt_port;

/**
 * One and only instance of the daemon.
 */
//daemon_t *charon;


struct kernel_vpp_ipsec;

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

	kernel_vpp_listener_t *listener;

	refcount_t nextspi;

	uint32_t mixspi;

	thread_t *keepalive;

	bool use_tunnel_mode_sa;

	stat_client_main_t *sm;
} kernel_vpp_ipsec_t;

typedef struct kernel_vpp_sa {
	uint32_t id;
	uint32_t stat_index;
	uint32_t peer_spi;
	uint32_t unique_id;
} kernel_vpp_sa_t;

/**
 * Hash function for IPsec SA
 */
static u_int
sa_hash (kernel_ipsec_sa_id_t *sa)
{
  return chunk_hash_inc (
    sa->src->get_address (sa->src),
    chunk_hash_inc (
      sa->dst->get_address (sa->dst),
      chunk_hash_inc (chunk_from_thing (sa->spi),
		      chunk_hash (chunk_from_thing (sa->proto)))));
}

/**
 * Equality function for IPsec SA
 */
static bool
sa_equals (kernel_ipsec_sa_id_t *sa, kernel_ipsec_sa_id_t *other_sa)
{
  return sa->src->ip_equals (sa->src, other_sa->src) &&
	 sa->dst->ip_equals (sa->dst, other_sa->dst) &&
	 sa->spi == other_sa->spi && sa->proto == other_sa->proto;
}

/**
 * Map an integer x with a one-to-one function using quadratic residues
 */
static u_int
permute (u_int x, u_int p)
{
  u_int qr;

  x = x % p;
  qr = ((uint64_t) x * x) % p;
  if (x <= p / 2)
    {
      return qr;
    }
  return p - qr;
}

/**
 * Initialize seeds for SPI generation
 */
static bool
init_spi (kernel_vpp_ipsec_t *this)
{
  bool ok = TRUE;
  rng_t *rng;

  rng = lib->crypto->create_rng (lib->crypto, RNG_STRONG);
  if (!rng)
    {
      return FALSE;
    }
  ok =
    rng->get_bytes (rng, sizeof (this->nextspi), (uint8_t *) &this->nextspi);
  if (ok)
    {
      ok =
	rng->get_bytes (rng, sizeof (this->mixspi), (uint8_t *) &this->mixspi);
    }
  rng->destroy (rng);
  return ok;
}

static void
sw_interface_details(void *user, struct naas_api_sw_interface *interface)
{
	uint32_t *sw_if_index;

	sw_if_index = user;
	*sw_if_index = interface->sw_if_index;
}

static uint32_t
get_sw_if_index(const char *if_name)
{
	int sw_if_index;

	sw_if_index = ~0;
	naas_api_sw_interface_dump(sw_interface_details, &sw_if_index, if_name);
	return sw_if_index;
}

static uint32_t
get_ipsec_sw_if_index(uint32_t instance)
{
	char if_name[64];

	snprintf(if_name, sizeof(if_name), "ipsec%d", instance);
	return get_sw_if_index(if_name);
}

static uint32_t
get_or_create_ipsec(kernel_vpp_ipsec_t *this, uint32_t unique_id)
{
	uint32_t sw_if_index;

	sw_if_index = get_ipsec_sw_if_index(unique_id);
	if (sw_if_index == ~0) {
		naas_api_ipsec_itf_create(unique_id, &sw_if_index);
		naas_api_sw_interface_set_unnumbered(1, this->loop_sw_if_index,	sw_if_index);
	}

	return sw_if_index;
}

METHOD (kernel_ipsec_t, ipsec_get_features, kernel_feature_t,
	kernel_vpp_ipsec_t *this)
{
  VAC_METHOD;
  return KERNEL_ESP_V3_TFC;
}

METHOD (kernel_ipsec_t, get_spi, status_t, kernel_vpp_ipsec_t *this,
	host_t *src, host_t *dst, uint8_t protocol, uint32_t *spi)
{
  static const u_int p = 268435399, offset = 0xc0000000;

  VAC_METHOD;
  *spi = htonl (offset + permute (ref_get (&this->nextspi) ^ this->mixspi, p));
  return SUCCESS;
}

METHOD (kernel_ipsec_t, get_cpi, status_t, kernel_vpp_ipsec_t *this,
	host_t *src, host_t *dst, uint16_t *cpi)
{
  VAC_METHOD;
  DBG1 (DBG_KNL, "get_cpi is not supported!!!!!!!!!!!!!!!!!!!!!!!!");
  return NOT_SUPPORTED;
}

/**
 * Helper struct for expiration events
 */
typedef struct
{

  kernel_vpp_ipsec_t *manager;

  kernel_ipsec_sa_id_t *sa_id;

  /**
   * 0 if this is a hard expire, otherwise the offset in s (soft->hard)
   */
  uint32_t hard_offset;

} vpp_sa_expired_t;

/**
 * Clean up expire data
 */
static void
expire_data_destroy (vpp_sa_expired_t *data)
{
  free (data);
}

/**
 * Callback for expiration events
 */
static job_requeue_t
sa_expired(vpp_sa_expired_t *expired)
{
	kernel_vpp_ipsec_t *this = expired->manager;
	kernel_vpp_sa_t *sa;
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

// enc_key
// enc_alg
// 
// int_key
// int_alg
//
// inbound  
// replay_window
// esn
// encap
// lifetime

//kernel_ipsec_update_sa_t

static kernel_vpp_sa_t *
kernel_vpp_sa_create(kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id)
{
	kernel_vpp_sa_t *sa;
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
	uint32_t sad_id, sw_if_index, stat_index;
	status_t rv;
	chunk_t src, dst;
	kernel_ipsec_sa_id_t key, peer_key;
	kernel_vpp_sa_t *sa, *peer_sa, *i_sa, *o_sa;
	int key_len;

	VAC_METHOD;

	ca = ia = 0;
	rv = FAILED;
	key_len = data->enc_key.len;
	sad_id = ref_get(&this->next_sad_id); 


  if ((data->enc_alg == ENCR_AES_CTR) ||
      (data->enc_alg == ENCR_AES_GCM_ICV8) ||
      (data->enc_alg == ENCR_AES_GCM_ICV12) ||
      (data->enc_alg == ENCR_AES_GCM_ICV16))
    {
      // See how enc_size is calculated at keymat_v2.derive_child_keys
      static const int SALT_SIZE = 4; 
      key_len = key_len - SALT_SIZE;
    }
  natt_port = lib->settings->get_int (
    lib->settings, "%s.plugins.socket-default.natt", IKEV2_NATT_PORT, lib->ns);
  memset (&mp, 0, sizeof (mp));
  u16 msg_id =
    vl_msg_api_get_msg_index ((u8 *) "ipsec_sad_entry_add_del_ab64b5c6");
  mp._vl_msg_id = htons (msg_id);
  mp.is_add = 1;
  mp.entry.sad_id = htonl (sad_id);
  mp.entry.spi = id->spi;
  mp.entry.protocol = id->proto == IPPROTO_ESP ? htonl (IPSEC_API_PROTO_ESP) :
							htonl (IPSEC_API_PROTO_AH);

  switch (data->enc_alg)
    {
    case ENCR_NULL:
      ca = IPSEC_API_CRYPTO_ALG_NONE;
      break;
    case ENCR_AES_CBC:
      switch (key_len * 8)
	{
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
	  DBG1 (DBG_KNL, "Key length %d is not supported by VPP!",
		key_len * 8);
	  goto error;
	}
      break;
    case ENCR_AES_CTR:
      switch (key_len * 8)
	{
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
	  DBG1 (DBG_KNL, "Key length %d is not supported by VPP!",
		key_len * 8);
	  goto error;
	}
      break;
    case ENCR_AES_GCM_ICV8:
    case ENCR_AES_GCM_ICV12:
    case ENCR_AES_GCM_ICV16:
      switch (key_len * 8)
	{
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
	  DBG1 (DBG_KNL, "Key length %d is not supported by VPP!",
		key_len * 8);
	  goto error;
	}
      break;
    case ENCR_DES:
      ca = IPSEC_API_CRYPTO_ALG_DES_CBC;
      break;
    case ENCR_3DES:
      ca = IPSEC_API_CRYPTO_ALG_3DES_CBC;
      break;
    default:
      DBG1 (DBG_KNL, "algorithm %N not supported by VPP!",
	    encryption_algorithm_names, data->enc_alg);
      goto error;
    }
  mp.entry.crypto_algorithm = htonl (ca);
  mp.entry.crypto_key.length = key_len < 128 ? key_len : 128;
  memcpy (mp.entry.crypto_key.data, data->enc_key.ptr,
	  mp.entry.crypto_key.length);

  // copy salt for AEAD algorithms
  if ((data->enc_alg == ENCR_AES_CTR) ||
      (data->enc_alg == ENCR_AES_GCM_ICV8) ||
      (data->enc_alg == ENCR_AES_GCM_ICV12) ||
      (data->enc_alg == ENCR_AES_GCM_ICV16))
    {
      memcpy (&mp.entry.salt, data->enc_key.ptr + mp.entry.crypto_key.length, 4);
    }

  switch (data->int_alg)
    {
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
      goto error;
      break;
    }
  mp.entry.integrity_algorithm = htonl (ia);
  mp.entry.integrity_key.length =
    data->int_key.len < 128 ? data->int_key.len : 128;
  memcpy (mp.entry.integrity_key.data, data->int_key.ptr,
	  mp.entry.integrity_key.length);

  int flags = IPSEC_API_SAD_FLAG_NONE;
  if (data->inbound)
    flags |= IPSEC_API_SAD_FLAG_IS_INBOUND;
  /* like the kernel-netlink plugin, anti-replay can be disabled with zero
   * replay_window, but window size cannot be customized for vpp */
  if (data->replay_window)
    flags |= IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY;
  if (data->esn)
    flags |= IPSEC_API_SAD_FLAG_USE_ESN;
  if (this->use_tunnel_mode_sa && data->mode == MODE_TUNNEL)
    {
      if (id->src->get_family (id->src) == AF_INET6)
	flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL_V6;
      else
	flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL;
    }
  if (data->encap)
    {
      DBG1 (DBG_KNL, "UDP encap!!!!!!!!!!!!!!!!!!!!");
      flags |= IPSEC_API_SAD_FLAG_UDP_ENCAP;
    }
  mp.entry.flags = htonl (flags);

  bool is_ipv6 = false;
  if (id->src->get_family (id->src) == AF_INET6)
    {
      is_ipv6 = true;
      mp.entry.tunnel_src.af = htonl (ADDRESS_IP6);
      mp.entry.tunnel_dst.af = htonl (ADDRESS_IP6);
    }
  else
    {
      mp.entry.tunnel_src.af = htonl (ADDRESS_IP4);
      mp.entry.tunnel_dst.af = htonl (ADDRESS_IP4);
    }
  src = id->src->get_address (id->src);
  memcpy (is_ipv6 ? mp.entry.tunnel_src.un.ip6 : mp.entry.tunnel_src.un.ip4,
	  src.ptr, src.len);
  dst = id->dst->get_address (id->dst);
  memcpy (is_ipv6 ? mp.entry.tunnel_dst.un.ip6 : mp.entry.tunnel_dst.un.ip4,
	  dst.ptr, dst.len);

  err = NAAS_API_INVOKE (mp, rmp);
  if (rmp)
    stat_index = ntohl(rmp->stat_index);
  naas_api_msg_free (rmp);
  if (err.num && err.type == NAAS_ERR_ERRNO)
    {
      DBG1 (DBG_KNL, "vac adding SA with SPI %.8x failed", htonl(id->spi));
      goto error;
    }
  if (err.num && err.type == NAAS_ERR_VNET)
    {
      DBG1 (DBG_KNL, "add SA failed rv:%d", err.num);
      goto error;
    }

	this->mutex->lock(this->mutex);
	key.src = id->src;
	key.dst = id->dst;
	key.spi = id->spi;
	key.proto = id->proto;

	sa = this->sas->get(this->sas, &key);
	if (sa != NULL) {
		sa->id = sad_id;
		peer_key.src = key.dst;
		peer_key.dst = key.src;
		peer_key.proto = key.proto;
		peer_key.spi = sa->peer_spi;

		peer_sa = this->sas->get(this->sas, &peer_key);
		if (peer_sa != NULL && peer_sa->id != ~0) {
			sw_if_index = get_or_create_ipsec(this, sa->unique_id);
			if (data->inbound) {
				i_sa = sa;
				o_sa = peer_sa;
			} else {
				i_sa = peer_sa;
				o_sa = sa;
			}
			naas_api_ipsec_tunnel_protect_update(sw_if_index, i_sa->id, o_sa->id);
		}
	} else {
		sa = kernel_vpp_sa_create(this, &key);
		sa->id = sad_id;
	}

	sa->stat_index = stat_index;


	schedule_expiration(this, data->lifetime, id);
	rv = SUCCESS;

error:
	this->mutex->unlock(this->mutex);
	return rv;
}

METHOD(kernel_ipsec_t, query_sa, status_t, kernel_vpp_ipsec_t *this,
		kernel_ipsec_sa_id_t *id, kernel_ipsec_query_sa_t *data,
	uint64_t *bytes, uint64_t *packets, time_t *time)
{
	status_t rv;
	kernel_vpp_sa_t *sa;
	u32 *dir;
	int i, k, rv_stat;
	stat_segment_data_t *res;
	u8 **pattern;
	uint64_t res_bytes;
	uint64_t res_packets;

	VAC_METHOD;

	dir = NULL;
	rv = FAILED;
	res = NULL;
	pattern = NULL;
	res_bytes = 0;
	res_packets = 0;

	this->mutex->lock(this->mutex);
	sa = this->sas->get(this->sas, id);
	if (!sa) {
		this->mutex->unlock (this->mutex);
		DBG1 (DBG_KNL, "CHILD_SA withs SPI %.8x not found", htonl(id->spi));
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
  /* i-loop for each results find by pattern - here two:
   * 1. /net/ipsec/sa
   * 2. /net/ipsec/sa/lost
   */
  for (i = 0; i < vec_len (res); i++)
    {
      switch (res[i].type)
	{
	/* type for how many packets are lost */
	case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
	  if (res[i].simple_counter_vec == 0)
	    continue;
	  break;
	/* type for counter for each SA */
	case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
	  if (res[i].combined_counter_vec == 0)
	    continue;
	  /* k-loop for each threads - that you run VPP */
	  for (k = 0; k < vec_len (res[i].combined_counter_vec); k++)
	    {
	      if (sa->stat_index <= vec_len (res[i].combined_counter_vec[k]))
		{
		  DBG1(DBG_KNL, "Thread: %d, Packets: %lu, Bytes: %lu", k,
			res[i].combined_counter_vec[k][sa->stat_index].packets,
			res[i].combined_counter_vec[k][sa->stat_index].bytes);
		  res_bytes +=
		    res[i].combined_counter_vec[k][sa->stat_index].bytes;
		  res_packets +=
		    res[i].combined_counter_vec[k][sa->stat_index].packets;
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

  vec_free (pattern);
  vec_free (dir);
  stat_segment_data_free (res);

  if (bytes)
    {
      *bytes = res_bytes;
    }
  if (packets)
    {
      *packets = res_packets;
    }
  if (time)
    {
      *time = 0;
    }

	this->mutex->unlock (this->mutex);
	rv = SUCCESS;
	return rv;
}

status_t
kernel_vpp_del_sa(kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id)
{
	naas_err_t err;
	vl_api_ipsec_sad_entry_add_del_t mp;
	vl_api_ipsec_sad_entry_add_del_reply_t *rmp;
	status_t rv;
	kernel_vpp_sa_t *sa;

	VAC_METHOD;

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
	u16 msg_id = vl_msg_api_get_msg_index ((u8 *) "ipsec_sad_entry_add_del_ab64b5c6");
	mp._vl_msg_id = htons (msg_id);
	mp.entry.sad_id = htonl(sa->id);

  	err = NAAS_API_INVOKE (mp, rmp);
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
	VAC_METHOD;
	return kernel_vpp_del_sa(this, id);
}

METHOD(kernel_ipsec_t, update_sa, status_t, kernel_vpp_ipsec_t *this,
		kernel_ipsec_sa_id_t *id, kernel_ipsec_update_sa_t *data)
{
	VAC_METHOD;

	DBG1(DBG_KNL, "update SA_CHILD %#H == %#H with SPI %.8x to %#H == %#H not supported",
			id->src, id->dst, htonl(id->spi),
			data->new_src, data->new_dst);

	return NOT_SUPPORTED;
}

METHOD (kernel_ipsec_t, flush_sas, status_t, kernel_vpp_ipsec_t *this)
{
  VAC_METHOD;
  return SUCCESS;
#if 0
  enumerator_t *enumerator;
  int out_len;
  char *out;
  vl_api_ipsec_sad_entry_add_del_t *mp = NULL;
  vl_api_ipsec_sad_entry_add_del_reply_t *rmp = NULL;
  kernel_vpp_child_sa_t *sa = NULL;
  status_t rv = FAILED;

  this->mutex->lock (this->mutex);
  enumerator = this->sas->create_enumerator (this->sas);
  while (enumerator->enumerate (enumerator, &sa))
    {
      mp = vl_msg_api_alloc (sizeof (*mp));
      memset (mp, 0, sizeof (*mp));
      u16 msg_id =
	vl_msg_api_get_msg_index ((u8 *) "ipsec_sad_entry_add_del_ab64b5c6");
      mp->_vl_msg_id = htons (msg_id);
      mp->entry.sad_id = htonl (sa->id);
      mp->is_add = 0;
      VAC_LOG("ipsec_sad_entry_add_del");
      if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
	{
	  DBG1 (DBG_KNL, "flush_sas failed!!!!");
	  goto error;
	}
      rmp = (void *) out;
      if (rmp->retval)
	{
	  DBG1 (DBG_KNL, "flush_sas failed!!!! rv: %d", ntohl (rmp->retval));
	  goto error;
	}
      free (out);
      vl_msg_api_free (mp);
      this->sas->remove_at (this->sas, enumerator);
      free (sa);
    }
  rv = SUCCESS;
error:
  if (out != NULL)
    free (out);
  if (mp != NULL)
    vl_msg_api_free (mp);

  enumerator->destroy (enumerator);
  this->mutex->unlock (this->mutex);

  return rv;
#endif
}

METHOD(kernel_ipsec_t, add_policy, status_t, kernel_vpp_ipsec_t *this,
		kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{
	VAC_METHOD;
	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
		kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
		kernel_ipsec_query_policy_t *data, time_t *use_time)
{
	VAC_METHOD;
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_policy, status_t, kernel_vpp_ipsec_t *this,
		kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{
	VAC_METHOD;
	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_policies, status_t, kernel_vpp_ipsec_t *this)
{
	VAC_METHOD;
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, bypass_socket, bool, kernel_vpp_ipsec_t *this, int fd, int family)
{
	VAC_METHOD;
	return FALSE;
}

METHOD (kernel_ipsec_t, enable_udp_decap, bool,
		kernel_vpp_ipsec_t *this, int fd, int family, u_int16_t port)
{
	VAC_METHOD;
	DBG1(DBG_KNL, "enable_udp_decap not supported!!!!!!!!!!!!!!!!!!!!!!!!!");
	return FALSE;
}

METHOD(kernel_ipsec_t, ipsec_destroy, void, kernel_vpp_ipsec_t *this)
{
	charon->bus->remove_listener(charon->bus, &this->listener->public);
	free(this->listener);
	this->keepalive->cancel(this->keepalive);
	this->mutex->destroy(this->mutex);
	this->sas->destroy(this->sas);
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
	return TRUE;
}

METHOD(listener_t, child_state_change, bool,
	kernel_vpp_listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
	child_sa_state_t state)
{
	return TRUE;
}

static void
kernel_vpp_child_up(kernel_vpp_listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	uint32_t unique_id, sw_if_index, i_spi, o_spi;
	protocol_id_t proto;
	kernel_ipsec_sa_id_t o_key, i_key;
	kernel_vpp_sa_t *i_sa, *o_sa;

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

	sw_if_index = get_or_create_ipsec(this->ipsec, unique_id);

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
}

METHOD(listener_t, child_updown, bool,
		kernel_vpp_listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa, bool up)
{
	uint32_t unique_id, i_spi, o_spi, sw_if_index;

	unique_id = ike_sa->get_unique_id(ike_sa);

	i_spi = child_sa->get_spi(child_sa, TRUE);
	o_spi = child_sa->get_spi(child_sa, FALSE);

	VAC_LOG("child_%s %.8x_i %.8x_o", up ? "up" : "down", ntohl(i_spi), ntohl(o_spi));

	if (up) {
		kernel_vpp_child_up(this, ike_sa, child_sa);
	} else {
		sw_if_index = get_ipsec_sw_if_index(unique_id);
		if (sw_if_index != ~0) {
			naas_api_ipsec_itf_delete(sw_if_index);
		}
	}

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

	VAC_LOG("child_rekey %.8x_i %.8x_o => %.8x_i %.8x_o",
			ntohl(old_i_spi), ntohl(old_o_spi), ntohl(new_i_spi), ntohl(new_o_spi));

	kernel_vpp_child_up(this, ike_sa, new);

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
		.use_tunnel_mode_sa = lib->settings->get_bool(lib->settings,
				    "%s.plugins.kernel-vpp.use_tunnel_mode_sa",
				    TRUE, lib->ns),
		.sm = NULL,
	);

	this->keepalive = thread_create((thread_main_t)keepalive_fn, this);

	if (!init_spi (this)) {
		ipsec_destroy (this);
		return NULL;
	}

	this->listener = kernel_vpp_listener_create(this);
	charon->bus->add_listener(charon->bus, &this->listener->public);

	return this;
}
//=========================================================

typedef struct private_kernel_vpp_plugin {
  	kernel_vpp_plugin_t public;
} private_kernel_vpp_plugin_t;

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
