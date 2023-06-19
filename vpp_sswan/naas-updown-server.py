#!/usr/bin/python3
#
# pip3 install nats-py
import os
import sys
import time
import traceback
import fnmatch
import asyncio
import ipaddress
import subprocess
import argparse
import nats
from vpp_papi import VPPApiJSONFiles
from vpp_papi import vpp_papi


test_msg = "ipsec1 48.0.0.0/24 12 1"
VPP_JSON_DIR = '/usr/share/vpp/api/core/'
API_FILE_SUFFIX = '*.api.json'
SR_STEER_IPV4 = 4


def argparse_ip_address(s):
    try:
        return ipaddress.ip_address(s)
    except Exception as exc:
        raise argparse.ArgumentTypeError(str(exc))


def system(cmd, fault_tollerance=False):
	proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	try:
		proc.communicate(timeout = 5)
	except Exception as exc:
		proc.kill();
		raise exc

	rc = proc.returncode

	if rc != 0 and not fault_tollerance:
		raise RuntimeError("Command '%s' failed with code '%d'" % (cmd, rc))
        
	return rc


def load_json_api_files(json_dir=VPP_JSON_DIR, suffix=API_FILE_SUFFIX):
	jsonfiles = []
	for root, dirnames, filenames in os.walk(json_dir):
		for filename in fnmatch.filter(filenames, suffix):
			jsonfiles.append(os.path.join(json_dir, filename))
	return jsonfiles


def connect_vpp(jsonfiles):                                                  
	vpp = vpp_papi.VPPApiClient(apifiles=jsonfiles)
	vpp.connect("naas-updown-server")
	return vpp


def process_msg(vpp, msg):
	args = msg.split(' ')

	intf = args[1]
	prefix = ipaddress.ip_network(args[2])
	prefix.network_address += 1
	vrf = int(args[3])
	pod = int(args[4])

	bsid = "2999:%d:%d:1::" % (pod, vrf)

	if args[0] == 'add':
		system("ip link add dev VRF%d type vrf table %d" % (vrf, vrf))
		system("ip link add %s type dummy" % intf)
		system("ip link set dev %s master VRF%d" % (intf, vrf))
		system("ip add add %s dev %s" % (prefix, intf));
		system("ip link set dev %s up" % intf);

		segs = [None] * 16
		segs[0] = "2aaa:%d:%d:1::" % (pod, vrf)
		vpp.api.sr_policy_add(bsid_addr = bsid,
				weight = 1,
				is_encap = 1,
				sids = { "num_sids": 1, "sids": segs })

		vpp.api.sr_steering_add_del(is_del = 0,
			bsid_addr = bsid,
			table_id = vrf,
			prefix = { "address": prefix.network_address, "len": prefix.prefixlen },
			traffic_type = SR_STEER_IPV4)

	else:
		vpp.api.sr_steering_add_del(is_del = 1,
			bsid_addr = bsid,
			table_id = vrf,
			prefix = { "address": prefix.network_address, "len": prefix.prefixlen },
			traffic_type = SR_STEER_IPV4)

		vpp.api.sr_policy_del(bsid_addr = bsid)
		system("ip link del %s" % intf);
		system("ip link del VRF%d" % vrf)



async def main(args):
	nc = await nats.connect(args.nats_server)

	sub = await nc.subscribe("updown")

	while True:
		try:
			msg = await sub.next_msg()
			process_msg(msg)
		except nats.errors.TimeoutError:
			pass
		except Exception:
			print(traceback.format_exc())
			print(sys.exc_info()[2])

	await nc.close()


if __name__ == '__main__':
	#process_msg(vpp, "add " + test_msg)
	#process_msg(vpp, "del " + test_msg)
	#return

	ap = argparse.ArgumentParser()
	ap.add_argument("--nats-server", metavar="host", type=str, default="localhost",
			help="Specify nats server ip address")

	args = ap.parse_args()

	vpp = connect_vpp(load_json_api_files())
	asyncio.run(main(args))

