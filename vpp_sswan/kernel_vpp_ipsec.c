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

#include <daemon.h>
#include <utils/debug.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/vnet.h>
#include <collections/hashtable.h>
#include <threading/mutex.h>
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

#include "kernel_vpp_ipsec.h"
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

#define PRIO_BASE 384

/**
 * Every 2 seconds, the thread responsible for collecting the available
 * interfaces will be executed.
 * Retrying 5 times every 1 second ensures that there is enough time to check
 * if the interface will be available.
 */
#define N_RETRY_GET_IF 5

u32 natt_port;

/**
 * One and only instance of the daemon.
 */
daemon_t *charon;

typedef struct private_kernel_vpp_ipsec_t private_kernel_vpp_ipsec_t;

/**
 * Private variables of kernel_vpp_ipsec class.
 */
struct private_kernel_vpp_ipsec_t
{

  /**
   * Public interface
   */
  kernel_vpp_ipsec_t public;

  /**
   * Next security association database entry ID to allocate
   */
  refcount_t next_sad_id;
  int loop_sw_if_index;


  /**
   * Mutex to lock access to installed policies
   */
  mutex_t *mutex;

  /**
   * Hash table of instaled SA, as kernel_ipsec_sa_id_t => sa_t
   */
  hashtable_t *sas;

  hashtable_t *in_sas;

  /**
   * Hash table of security policy databases, as nterface => spd_t
   */
  hashtable_t *spds;

  /**
   * Linked list of installed routes
   */
  linked_list_t *routes;

  /**
   * Next SPI to allocate
   */
  refcount_t nextspi;

  /**
   * Mix value to distribute SPI allocation randomly
   */
  uint32_t mixspi;

  /**
   * Whether to install routes along policies
   */
  bool install_routes;

  /**
   * Whether to install SAs with tunnel flag. Disabling this can be useful
   * in some scenarios e.g. using SAs to "ipsec tunnel protect" for the
   * route-based IPsec
   */
  bool use_tunnel_mode_sa;

  /**
   * Connections to VPP Stats
   */
  stat_client_main_t *sm;
};

/**
 * Security association entry
 */
typedef struct
{
  /** VPP SA ID */
  uint32_t sa_id;
  uint32_t stat_index;
  kernel_ipsec_sa_id_t *sa_id_p;
} sa_t;

/**
 * (Un)-install a single route
 */

/*static void
manage_route (private_kernel_vpp_ipsec_t *this, bool add,
	      traffic_selector_t *dst_ts, host_t *src, host_t *dst)
{
  host_t *dst_net = NULL, *gateway = NULL;
  uint8_t prefixlen;
  char *if_name = NULL;
  route_entry_t *route;
  bool route_exist = FALSE;

  char *netmask = "255.255.255.0";
  char *tap_gateway = "1.1.1.1";
  int arp_rc = 0;

  if (dst->is_anyaddr (dst))
    {
      return;
    }
  gateway =
    charon->kernel->get_nexthop (charon->kernel, dst, -1, NULL, &if_name);
  dst_ts->to_subnet (dst_ts, &dst_net, &prefixlen);
  if (!if_name)
    {
      if (src->is_anyaddr (src))
	{
	  goto error;
	}
      if (!charon->kernel->get_interface (charon->kernel, src, &if_name))
	{
	  goto error;
	}
    }
  route_exist =
    this->routes->find_first (this->routes, route_equals, (void **) &route,
			      if_name, gateway, dst_net, &prefixlen);
  if (add)
    {
      DBG2 (DBG_KNL, "installing route: %H/%d via %H dev %s", dst_net,
	    prefixlen, gateway, if_name);
      if (route_exist)
	{
	  unsigned int refs_num = ref_get (&route->refs);
	  DBG2 (DBG_KNL, "add route but it exist %d", refs_num);
	}
      else
	{
	  INIT (route, .if_name = strdup (if_name),
		.gateway = gateway->clone (gateway),
		.dst_net = dst_net->clone (dst_net), .prefixlen = prefixlen,
		.refs = 1, );
	  this->routes->insert_last (this->routes, route);
	  charon->kernel->add_route (charon->kernel,
				     dst_net->get_address (dst_net), prefixlen,
				     gateway, dst, if_name, 1);
	}

      add_Route ((void *)dst_net->get_address (dst_net).ptr,
		 dst_net->get_address (dst_net).len, netmask, tap_gateway);

      arp_rc = set_arp ((void *)gateway->get_address (gateway).ptr, if_name, TRUE);
      if (arp_rc)
	DBG2 (DBG_KNL, "arpGet success!\n");
    }
  else
    {
      DBG2 (DBG_KNL, "uninstalling route: %H/%d via %H dev %s", dst_net,
	    prefixlen, gateway, if_name);
      if (!route_exist)
	{
	  DBG2 (DBG_KNL, "del route but it not exist");
	  goto error;
	}
      if (ref_put (&route->refs))
	{
	  this->routes->remove (this->routes, route, NULL);
	  route_destroy (route);
	  charon->kernel->del_route (charon->kernel,
				     dst_net->get_address (dst_net), prefixlen,
				     gateway, dst, if_name, 1);
	}
    }
error:
  if (gateway != NULL)
    gateway->destroy (gateway);
  if (dst_net != NULL)
    dst_net->destroy (dst_net);
  if (if_name != NULL)
    free (if_name);
  return;
}*/

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
 * Hash function for interface
 */
static u_int
interface_hash (char *interface)
{
  return chunk_hash (chunk_from_str (interface));
}

/**
 * Equality function for interface
 */
static bool
interface_equals (char *interface1, char *interface2)
{
  return streq (interface1, interface2);
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
init_spi (private_kernel_vpp_ipsec_t *this)
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

/**
 * Calculate policy priority
 */
#if 0
static uint32_t
calculate_priority (policy_priority_t policy_priority, traffic_selector_t *src,
		    traffic_selector_t *dst)
{
  uint32_t priority = PRIO_BASE;
  uint16_t port;
  uint8_t mask, proto;
  host_t *net;

  switch (policy_priority)
    {
    case POLICY_PRIORITY_FALLBACK:
      priority <<= 1;
      // fall-through 
    case POLICY_PRIORITY_ROUTED:
      priority <<= 1;
      // fall-through
    case POLICY_PRIORITY_DEFAULT:
      priority <<= 1;
      // fall-through
    case POLICY_PRIORITY_PASS:
      break;
    }
  // calculate priority based on selector size, small size = high prio
  src->to_subnet (src, &net, &mask);
  priority -= mask;
  proto = src->get_protocol (src);
  port = net->get_port (net);
  net->destroy (net);

  dst->to_subnet (dst, &net, &mask);
  priority -= mask;
  proto = max (proto, dst->get_protocol (dst));
  port = max (port, net->get_port (net));
  net->destroy (net);

  priority <<= 2; // make some room for the two flags
  priority += port ? 0 : 2;
  priority += proto ? 0 : 1;
  return priority;
}
#endif

/**
 * (Un)-install a security policy database
 */



static status_t
manage_policy(private_kernel_vpp_ipsec_t *this, bool add, kernel_ipsec_policy_id_t *id,
		kernel_ipsec_manage_policy_t *data)
{
	uint32_t reqid, sa_id, in_sa_id, sw_if_index;

	this->mutex->lock (this->mutex);

	reqid = data->sa->reqid;

	if (add) {
		kernel_ipsec_sa_id_t sa_key = {
			.src = data->src,
			.dst = data->dst,
			.proto = data->sa->esp.use ? IPPROTO_ESP : IPPROTO_AH,
			.spi = data->sa->esp.use ? data->sa->esp.spi : data->sa->ah.spi,
		};
		sa_t *sa = NULL;
		sa = this->sas->get(this->sas, &sa_key);
		sa_id = sa->sa_id;

		if (id->dir == POLICY_IN) {
			this->in_sas->put(this->in_sas, (void*)(uintptr_t)reqid, (void *)(uintptr_t)sa_id);
		}

		if (id->dir == POLICY_OUT) {
	//		in_sa_id = (uintptr_t)this->in_sas->get(this->in_sas, (void*)(uintptr_t)reqid);
			in_sa_id = (uintptr_t)this->in_sas->remove(this->in_sas, (void*)(uintptr_t)reqid);

			host_t *dst_net = NULL;
			struct sockaddr_in *addr;
			uint8_t prefixlen;
			id->dst_ts->to_subnet(id->dst_ts, &dst_net, &prefixlen);
			addr = (struct sockaddr_in *)dst_net->get_sockaddr(dst_net);


			VAC_LOG("add policy: sa=%d/%d, reqid=%d, dir=%d loop=%d",
				in_sa_id, sa_id, reqid, id->dir, this->loop_sw_if_index);
			naas_api_ipsec_itf_create(reqid, &sw_if_index);
			naas_api_sw_interface_set_unnumbered(1, this->loop_sw_if_index, sw_if_index);
			naas_api_sw_interface_set_flags(sw_if_index, IF_STATUS_API_FLAG_ADMIN_UP);
			naas_api_ip_route_add_del(1, addr->sin_addr, prefixlen, sw_if_index);
			naas_api_ipsec_tunnel_protect_update(sw_if_index, in_sa_id, sa_id);
		}

	} else {
		VAC_LOG("del policy: dir=%d", id->dir);
	}

	this->mutex->unlock (this->mutex);
	return SUCCESS;
}

METHOD (kernel_ipsec_t, get_features, kernel_feature_t,
	private_kernel_vpp_ipsec_t *this)
{
  VAC_METHOD;
  return KERNEL_ESP_V3_TFC;
}

METHOD (kernel_ipsec_t, get_spi, status_t, private_kernel_vpp_ipsec_t *this,
	host_t *src, host_t *dst, uint8_t protocol, uint32_t *spi)
{
  static const u_int p = 268435399, offset = 0xc0000000;

  VAC_METHOD;
  *spi = htonl (offset + permute (ref_get (&this->nextspi) ^ this->mixspi, p));
  return SUCCESS;
}

METHOD (kernel_ipsec_t, get_cpi, status_t, private_kernel_vpp_ipsec_t *this,
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

  private_kernel_vpp_ipsec_t *manager;

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
sa_expired (vpp_sa_expired_t *expired)
{
  private_kernel_vpp_ipsec_t *this = expired->manager;
  sa_t *sa;
  kernel_ipsec_sa_id_t *id = expired->sa_id;

  this->mutex->lock (this->mutex);
  sa = this->sas->get (this->sas, id);

  if (sa)
    {
      charon->kernel->expire (charon->kernel, id->proto, id->spi, id->dst,
			      FALSE);
    }

  if (id->src)
    id->src->destroy (id->src);
  if (id->dst)
    id->dst->destroy (id->dst);
  free (id);
  this->mutex->unlock (this->mutex);
  return JOB_REQUEUE_NONE;
}

/**
 * Schedule a job to handle IPsec SA expiration
 */
static void
schedule_expiration (private_kernel_vpp_ipsec_t *this,
		     kernel_ipsec_add_sa_t *entry,
		     kernel_ipsec_sa_id_t *entry2)
{
  lifetime_cfg_t *lifetime = entry->lifetime;
  vpp_sa_expired_t *expired;
  callback_job_t *job;
  uint32_t timeout;
  kernel_ipsec_sa_id_t *id;

  if (!lifetime->time.life)
    { /* no expiration at all */
      return;
    }

  INIT (id, .src = entry2->src->clone (entry2->src),
	.dst = entry2->dst->clone (entry2->dst), .spi = entry2->spi,
	.proto = entry2->proto, );

  INIT (expired, .manager = this, .sa_id = id, );

  /* schedule a rekey first, a hard timeout will be scheduled then, if any */
  expired->hard_offset = lifetime->time.life - lifetime->time.rekey;
  timeout = lifetime->time.rekey;

  if (lifetime->time.life <= lifetime->time.rekey || lifetime->time.rekey == 0)
    { /* no rekey, schedule hard timeout */
      expired->hard_offset = 0;
      timeout = lifetime->time.life;
    }

  job =
    callback_job_create ((callback_job_cb_t) sa_expired, expired,
			 (callback_job_cleanup_t) expire_data_destroy, NULL);
  lib->scheduler->schedule_job (lib->scheduler, (job_t *) job, timeout);
}


METHOD (kernel_ipsec_t, add_sa, status_t, private_kernel_vpp_ipsec_t *this,
	kernel_ipsec_sa_id_t *id, kernel_ipsec_add_sa_t *data)
{
  naas_err_t err;
  vl_api_ipsec_sad_entry_add_del_t mp;
  vl_api_ipsec_sad_entry_add_del_reply_t *rmp;
  uint32_t sad_id = ref_get (&this->next_sad_id);
  uint8_t ca = 0, ia = 0;
  status_t rv = FAILED;
  chunk_t src, dst;
  kernel_ipsec_sa_id_t *sa_id;
  sa_t *sa;
  int key_len = data->enc_key.len;

  VAC_METHOD;

  if ((data->enc_alg == ENCR_AES_CTR) ||
      (data->enc_alg == ENCR_AES_GCM_ICV8) ||
      (data->enc_alg == ENCR_AES_GCM_ICV12) ||
      (data->enc_alg == ENCR_AES_GCM_ICV16))
    {
      static const int SALT_SIZE =
	4; /* See how enc_size is calculated at keymat_v2.derive_child_keys */
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

  /* copy salt for AEAD algorithms */
  if ((data->enc_alg == ENCR_AES_CTR) ||
      (data->enc_alg == ENCR_AES_GCM_ICV8) ||
      (data->enc_alg == ENCR_AES_GCM_ICV12) ||
      (data->enc_alg == ENCR_AES_GCM_ICV16))
    {
      memcpy (&mp.entry.salt, data->enc_key.ptr + mp.entry.crypto_key.length,
	      4);
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

  VAC_LOG("api: ipsec_sad_entry_add_del");
  err = NAAS_API_INVOKE (mp, rmp);
  naas_api_msg_free (rmp);
  if (err.num && err.type == NAAS_ERR_ERRNO)
    {
      DBG1 (DBG_KNL, "vac adding SA failed");
      goto error;
    }
  if (err.num && err.type == NAAS_ERR_VNET)
    {
      DBG1 (DBG_KNL, "add SA failed rv:%d", err.num);
      goto error;
    }

  this->mutex->lock (this->mutex);
  INIT (sa_id, .src = id->src->clone (id->src),
	.dst = id->dst->clone (id->dst), .spi = id->spi, .proto = id->proto, );
  INIT (sa, .sa_id = sad_id, .stat_index = ntohl (rmp->stat_index),
	.sa_id_p = sa_id, );
  DBG4 (DBG_KNL, "put sa by its sa_id %x !!!!!!", sad_id);
  this->sas->put (this->sas, sa_id, sa);
  schedule_expiration (this, data, id);
  this->mutex->unlock (this->mutex);
  rv = SUCCESS;

error:
  return rv;
}

METHOD (kernel_ipsec_t, update_sa, status_t, private_kernel_vpp_ipsec_t *this,
	kernel_ipsec_sa_id_t *id, kernel_ipsec_update_sa_t *data)
{
  VAC_METHOD;

  DBG1 (DBG_KNL,
	"update sa not supported!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  return NOT_SUPPORTED;
}

METHOD (kernel_ipsec_t, query_sa, status_t, private_kernel_vpp_ipsec_t *this,
	kernel_ipsec_sa_id_t *id, kernel_ipsec_query_sa_t *data,
	uint64_t *bytes, uint64_t *packets, time_t *time)
{
  status_t rv = FAILED;
  sa_t *sa;
  u32 *dir = NULL;
  int i, k;
  stat_segment_data_t *res = NULL;
  u8 **pattern = 0;
  uint64_t res_bytes = 0;
  uint64_t res_packets = 0;

  VAC_METHOD;

  this->mutex->lock (this->mutex);
  sa = this->sas->get (this->sas, id);
  if (!sa)
    {
      this->mutex->unlock (this->mutex);
      DBG1 (DBG_KNL, "SA not found");
      return NOT_FOUND;
    }

  if (this->sm == NULL)
    {
      stat_client_main_t *sm = NULL;
      sm = stat_client_get ();

      if (!sm)
	{
	  DBG1 (DBG_KNL, "Not connecting with stats segmentation");
	  this->mutex->unlock (this->mutex);
	  return NOT_FOUND;
	}
      this->sm = sm;
      int rv_stat = stat_segment_connect_r ("/run/vpp/stats.sock", this->sm);
      if (rv_stat != 0)
	{
	  stat_client_free (this->sm);
	  this->sm = NULL;
	  DBG1 (DBG_KNL, "Not connecting with stats segmentation");
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
		  DBG4 (DBG_KNL, "Thread: %d, Packets: %lu, Bytes: %lu", k,
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

METHOD (kernel_ipsec_t, del_sa, status_t, private_kernel_vpp_ipsec_t *this,
	kernel_ipsec_sa_id_t *id, kernel_ipsec_del_sa_t *data)
{
  naas_err_t err;
  vl_api_ipsec_sad_entry_add_del_t mp;
  vl_api_ipsec_sad_entry_add_del_reply_t *rmp;
  status_t rv = FAILED;
  sa_t *sa;

  VAC_METHOD;

  this->mutex->lock (this->mutex);
  sa = this->sas->get (this->sas, id);
  if (!sa)
    {
      DBG1 (DBG_KNL, "SA not found");
      rv = NOT_FOUND;
      goto error;
    }
  memset (&mp, 0, sizeof (mp));
  mp.is_add = 0;
  u16 msg_id =
    vl_msg_api_get_msg_index ((u8 *) "ipsec_sad_entry_add_del_ab64b5c6");
  mp._vl_msg_id = htons (msg_id);
  mp.entry.sad_id = htonl (sa->sa_id);

  VAC_LOG("api: ipsec_sad_entry_add_del");
  err = NAAS_API_INVOKE (mp, rmp);
  naas_api_msg_free (rmp);
  if (err.num && err.type == NAAS_ERR_ERRNO)
    {
      DBG1 (DBG_KNL, "vac removing SA failed");
      goto error;
    }
  if (err.num && err.type == NAAS_ERR_VNET)
    {
      DBG1 (DBG_KNL, "del SA failed rv:%d", err.num);
      goto error;
    }

  this->sas->remove (this->sas, id);
  if (sa->sa_id_p)
    {
      if (sa->sa_id_p->src)
	sa->sa_id_p->src->destroy (sa->sa_id_p->src);
      if (sa->sa_id_p->dst)
	sa->sa_id_p->dst->destroy (sa->sa_id_p->dst);
      free (sa->sa_id_p);
    }
  free (sa);
  rv = SUCCESS;
error:
//  free (out);
//  vl_msg_api_free (mp);
  this->mutex->unlock (this->mutex);
  return rv;
}

METHOD (kernel_ipsec_t, flush_sas, status_t, private_kernel_vpp_ipsec_t *this)
{
  VAC_METHOD;
  return SUCCESS;
#if 0
  enumerator_t *enumerator;
  int out_len;
  char *out;
  vl_api_ipsec_sad_entry_add_del_t *mp = NULL;
  vl_api_ipsec_sad_entry_add_del_reply_t *rmp = NULL;
  sa_t *sa = NULL;
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
      mp->entry.sad_id = htonl (sa->sa_id);
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
      if (sa->sa_id_p)
	{
	  if (sa->sa_id_p->src)
	    sa->sa_id_p->src->destroy (sa->sa_id_p->src);
	  if (sa->sa_id_p->dst)
	    sa->sa_id_p->dst->destroy (sa->sa_id_p->dst);
	}
      free (out);
      vl_msg_api_free (mp);
      this->sas->remove_at (this->sas, enumerator);
      free (sa->sa_id_p);
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

METHOD (kernel_ipsec_t, add_policy, status_t, private_kernel_vpp_ipsec_t *this,
	kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{
  VAC_METHOD;
  return manage_policy (this, TRUE, id, data);
}

METHOD (kernel_ipsec_t, query_policy, status_t,
	private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_query_policy_t *data, time_t *use_time)
{
  VAC_METHOD;
  return NOT_SUPPORTED;
}

METHOD (kernel_ipsec_t, del_policy, status_t, private_kernel_vpp_ipsec_t *this,
	kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{
  VAC_METHOD;
  return manage_policy (this, FALSE, id, data);
}

METHOD (kernel_ipsec_t, flush_policies, status_t,
	private_kernel_vpp_ipsec_t *this)
{
  VAC_METHOD;
  return NOT_SUPPORTED;
}

METHOD (kernel_ipsec_t, bypass_socket, bool, private_kernel_vpp_ipsec_t *this,
	int fd, int family)
{
  VAC_METHOD;
  return FALSE;
}

METHOD (kernel_ipsec_t, enable_udp_decap, bool,
	private_kernel_vpp_ipsec_t *this, int fd, int family, u_int16_t port)
{
  VAC_METHOD;
  DBG1 (DBG_KNL, "enable_udp_decap not supported!!!!!!!!!!!!!!!!!!!!!!!!!");
  return FALSE;
}

METHOD (kernel_ipsec_t, destroy, void, private_kernel_vpp_ipsec_t *this)
{
  VAC_METHOD;
  this->mutex->destroy (this->mutex);
  this->sas->destroy (this->sas);
  this->spds->destroy (this->spds);
  this->routes->destroy (this->routes);
  if (this->sm)
    {
      stat_segment_disconnect_r (this->sm);
      stat_client_free (this->sm);
      this->sm = NULL;
    }
  free (this);
}

kernel_vpp_ipsec_t *
kernel_vpp_ipsec_create ()
{
  uint32_t sw_if_index;
  private_kernel_vpp_ipsec_t *this;

  naas_api_create_loopback(&sw_if_index);

  INIT(this,
        .public = {
            .interface = {
                .get_features = _get_features,
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
                .destroy = _destroy,
            },
        },
        .next_sad_id = 0,
	.loop_sw_if_index = sw_if_index,
        .mutex = mutex_create(MUTEX_TYPE_DEFAULT),
        .sas = hashtable_create((hashtable_hash_t)sa_hash,
                                (hashtable_equals_t)sa_equals, 32),
	.in_sas = hashtable_create(hashtable_hash_ptr, hashtable_equals_ptr, 4),
        .spds = hashtable_create((hashtable_hash_t)interface_hash,
                                 (hashtable_equals_t)interface_equals, 4),
        .routes = linked_list_create(),
        .install_routes = lib->settings->get_bool(lib->settings,
                            "%s.install_routes", TRUE, lib->ns),
        .use_tunnel_mode_sa = lib->settings->get_bool(lib->settings,
                            "%s.plugins.kernel-vpp.use_tunnel_mode_sa",
                            TRUE, lib->ns),
        .sm = NULL,
    );

  if (!init_spi (this))
    {
      destroy (this);
      return NULL;
    }

  return &this->public;
}
