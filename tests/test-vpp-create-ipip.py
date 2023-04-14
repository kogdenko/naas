#!/usr/bin/python3

import sys
import json
import ipaddress
#import tempfile
import naas







def check_retval(d):
	assert(d['retval'] == 0)


def check_reply_retval(reply):
	check_retval(json.loads(reply))


def vat2(request):
	with open("/tmp/vpp-10k-ipip.json", 'wt') as tmp:
		tmp.write(request)
		tmp.close()
		out, err = naas.system("vat2 -f %s" % tmp.name)
		if err != None and len(err) != 0:
			raise RuntimeError("vat2 failed:\n%s" % err)
		return out


def vpp_create_loopback():
	reply = vat2('''[{
	"_msgname": "create_loopback",
	"_crc": "42bb5d22",
	"mac_address": "00:00:00:00:00:00"
}]
''')
	d = json.loads(reply)
	return d['sw_if_index']


def vpp_sw_interface_set_flags(sw_if_index, flags):
	reply = vat2('''[{
	"_msgname": "sw_interface_set_flags",
	"_crc": "f5aec1b8",
	"sw_if_index": %d,
	"flags": "%s"
}]
''' % (sw_if_index, flags))
	check_reply_retval(reply)


def vpp_hw_interface_set_mtu(sw_if_index, mtu):
	reply = vat2('''[{
	"_msgname": "hw_interface_set_mtu",
	"_crc": "e6746899",
	"sw_if_index": %d,
	"mtu": %d
}]
''' % (sw_if_index, mtu))
	check_reply_retval(reply)


def vpp_sw_interface_add_del_address(sw_if_index, prefix_ip, prefix_mask):
	reply = vat2('''[{
	"_msgname":     "sw_interface_add_del_address",
	"_crc": "5463d73b",
	"sw_if_index": %d,
	"is_add": true,
	"del_all": false,
	"prefix":  "%s/%d"
}]''' % (sw_if_index, prefix_ip, prefix_mask))
	check_reply_retval(reply)


def vpp_ipip_add_tunnel(sw_if_index, src, dst):
	reply = vat2('''[{
	"_msgname":     "ipip_add_tunnel",
	"_crc": "2ac399f5",
	"tunnel": {
		"instance": 4294967295,
		"src": "%s",
		"dst": "%s",
		"sw_if_index": %d,
		"table_id": 0,
		"flags": "TUNNEL_API_ENCAP_DECAP_FLAG_NONE",
		"mode": "TUNNEL_API_MODE_P2P",
		"dscp": "IP_API_DSCP_CS0"
	}
}]''' % (src, dst, sw_if_index))
	d = json.loads(reply)
	check_retval(d)
	return d['sw_if_index']


def vpp_ipsec_sad_entry_add(spi):
	reply = vat2('''[{
	"_msgname": "ipsec_sad_entry_add",
	"_crc": "50229353",
	"entry": {
		"sad_id": %d,
		"spi": %d,
		"protocol": "IPSEC_API_PROTO_ESP",
		"crypto_algorithm": "IPSEC_API_CRYPTO_ALG_AES_CBC_128",
		"crypto_key": {
			"length": 16,
			"data": "0x00000000: 00000000000000000000000000000000"
		},
		"integrity_algorithm": "IPSEC_API_INTEG_ALG_SHA_512_256",
		"integrity_key": {
			"length": 64,
			"data": "0x00000000: 0000000000000000000000000000000000000000000000000000000000000000\\n  00000020: 0000000000000000000000000000000000000000000000000000000000000000"
		},
		"flags": "IPSEC_API_SAD_FLAG_NONE",
		"tunnel": {
			"instance": 0,
			"src": "0.0.0.0",
			"dst": "0.0.0.0",
			"sw_if_index": 0,
			"table_id": 0,
			"encap_decap_flags": "TUNNEL_API_ENCAP_DECAP_FLAG_NONE",
			"mode": "TUNNEL_API_MODE_P2P",
			"flags": ["IPSEC_API_SAD_FLAG_IS_INBOUND"],
			"dscp": "IP_API_DSCP_CS0",
			"hop_limit": 0
		},
		"salt": 0,
		"udp_src_port": 65535,
		"udp_dst_port": 65535
	}
}]''' % (spi, spi))
	check_reply_retval(reply)


def vpp_ipsec_tunnel_protect_update(sw_if_index, sa_out, sa_in):
	reply = vat2('''[{
	"_msgname":     "ipsec_tunnel_protect_update",
	"_crc": "30d5f133",
	"tunnel":       {
		"sw_if_index": %d,
		"nh": "0.0.0.0",
		"sa_out": %d,
		"n_sa_in": 1,
		"sa_in": [%d]
	}
}]''' % (sw_if_index, sa_out, sa_in))
	check_reply_retval(reply)


def vpp_sw_interface_set_unnumbered(sw_if_index, unnumbered_sw_if_index):
	reply = vat2('''[{
	"_msgname":     "sw_interface_set_unnumbered",
	"_crc": "154a6439",
	"sw_if_index": %d,
	"unnumbered_sw_if_index": %d,
	"is_add": true
}]''' % (sw_if_index, unnumbered_sw_if_index))
	check_reply_retval(reply)


def print_progress(i, name):
	if (i + 1) % 100 == 0:
		print("%d %s" % (i + 1, name))

tunnels_num = 10000

loop0 = vpp_create_loopback()

vpp_sw_interface_set_flags(loop0, "IF_STATUS_API_FLAG_ADMIN_UP")

src = ipaddress.IPv4Address('1.1.1.1')

vpp_sw_interface_add_del_address(loop0, src, 32)

dst = ipaddress.IPv4Address('2.2.1.1')

ipip = []
for i in range(0, tunnels_num):
	ipip.append(vpp_ipip_add_tunnel(loop0, src, dst))
	dst += 1
	print_progress(i, "ipip_add_tunnel")

for i in range(0, tunnels_num):
	vpp_ipsec_sad_entry_add(100000 + 2*i)
	vpp_ipsec_sad_entry_add(100000 + 2*i + 1)
	print_progress(i, "ipsec_sad_entry_add")


for i in range(0, tunnels_num):
	vpp_ipsec_tunnel_protect_update(ipip[i], 100000 + 2*i, 100000 + 2*i + 1)
	print_progress(i, "ipsec_tunnel_protect_update")

for i in range(0, tunnels_num):
	vpp_sw_interface_set_unnumbered(ipip[i], loop0)
	print_progress(i, "sw_interface_set_unnumbered")

for i in range(0, tunnels_num):
	vpp_sw_interface_set_flags(ipip[i], "IF_STATUS_API_FLAG_ADMIN_UP")
	print_progress(i, "sw_interface_set_flags")
