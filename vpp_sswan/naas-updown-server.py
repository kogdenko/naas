#!/usr/bin/python3
#
# pip3 install nats-py
# pip3 install mysql-connector-python
import os
import sys
import time
import traceback
import fnmatch
import asyncio
import ipaddress
import subprocess
import argparse
import mysql.connector
import nats
from vpp_papi import VPPApiJSONFiles
from vpp_papi import vpp_papi


VPP_JSON_DIR = '/usr/share/vpp/api/core/'
API_FILE_SUFFIX = '*.api.json'
SR_STEER_IPV4 = 4


def argparse_ip_address(s):
    try:
        return ipaddress.ip_address(s)
    except Exception as exc:
        raise argparse.ArgumentTypeError(str(exc))


def bytes_to_str(b):
    return b.decode('utf-8').strip()


def system(cmd):
	proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	try:
		out, err = proc.communicate(timeout = 5)
	except Exception as exc:
		proc.kill();
		raise exc

	rc = proc.returncode

	if rc != 0:
		out = bytes_to_str(out)
		err = bytes_to_str(err)
		log = "$ %s\n$? = %d" % (cmd, rc)
		if len(out):
			log += "\n%s" % out
		if len(err):
			log += "\n%s" % err
		print(log)

	return rc


def load_json_api_files(json_dir=VPP_JSON_DIR, suffix=API_FILE_SUFFIX):
	jsonfiles = []
	for root, dirnames, filenames in os.walk(json_dir):
		for filename in fnmatch.filter(filenames, suffix):
			jsonfiles.append(os.path.join(json_dir, filename))
	return jsonfiles


class Server:
	def connect_vpp(self, jsonfiles):
		self.vpp = vpp_papi.VPPApiClient(apifiles=jsonfiles)
		self.vpp.connect("naas-updown-server")


	def mysql_execute(self, cmd, *args):
		try:
			mysql_cursor = self.mysql_conn.cursor(buffered = True)
			mysql_cursor.execute(cmd, *args);
		except mysql.connector.errors.ProgrammingError as exc:
			raise RuntimeError("mysql query '%s' failed" % cmd) from exc
		return mysql_cursor


	# CREATE USER 'naas'@'192.168.122.2' IDENTIFIED BY 'qwerty';
	# GRANT ALL PRIVILEGES ON naas.* TO 'naas'@'192.168.122.2';
	# FLUSH PRIVILEGES;
	def connect_mysql(self, host, user, password):
		self.mysql_conn = mysql.connector.connect(host=host, user=user, password=password,
				database="naas")
		self.mysql_execute("create table if not exists conns ("
				"pod INT,"
				"reqid INT,"
				"ts varchar(63),"
				"vrf int,"
				"primary key(pod, reqid)"
				")")


	# nats --server 192.168.122.1 pub shutdown "1"
	def process_shutdown(self, pod):
		mysql_cursor = self.mysql_execute("select * from conns where pod = %d" % pod)
		while True:
			row = mysql_cursor.fetchone()
			if row == None:
				break
			assert(len(row) == 4)
			pod = int(row[0])
			reqid = int(row[1])
			ts = str(row[2])
			vrf = int(row[3])
			self.process_updown(True, "del", reqid, ts, vrf, pod)

		self.mysql_execute("delete from conns where pod = %d" % (pod))
		self.mysql_conn.commit()


	def add_policy(self, bsid, prefix, vrf, pod):
		segs = [None] * 16
		segs[0] = "2aaa:%d:%d:1::" % (pod, vrf)
		self.vpp.api.sr_policy_add(bsid_addr = bsid,
				weight = 1,
				is_encap = 1,
				sids = { "num_sids": 1, "sids": segs })

		self.vpp.api.sr_steering_add_del(is_del = 0,
			bsid_addr = bsid,
			table_id = vrf,
			prefix = { "address": prefix.network_address, "len": prefix.prefixlen },
			traffic_type = SR_STEER_IPV4)


	def del_policy(self, bsid, prefix, vrf):
		self.vpp.api.sr_steering_add_del(is_del = 1,
				bsid_addr = bsid,
				table_id = vrf,
				prefix = { "address": prefix.network_address, "len": prefix.prefixlen },
				traffic_type = SR_STEER_IPV4)

		self.vpp.api.sr_policy_del(bsid_addr = bsid)


	def insert_into_conns(self, pod, reqid, ts, vrf):
		mysql_cmd = ("insert into conns (pod, reqid, ts, vrf) values (%d, %d, \"%s\", %d)" %
				(pod, reqid, ts, vrf))
		self.mysql_execute(mysql_cmd)
		self.mysql_conn.commit()


	def delete_from_conns(self, pod, reqid):	
		mysql_cmd = "delete from conns where pod = %d and reqid = %d" % (pod, reqid)
		self.mysql_execute(mysql_cmd)
		self.mysql_conn.commit()


	# nats --server 192.168.122.1 pub updown "add 1 48.0.0.0/24 12 1"
	def process_updown(self, to_mysql, action, reqid, ts, vrf, pod):
		prefix = ipaddress.ip_network(ts)
		prefix.network_address += 1
		intf = "ipsec" + str(pod) + "_" + str(reqid)

		bsid = "2999:%d:%d:1::" % (pod, vrf)

		policy_key = str(vrf) + "_" + ts
		policy_ref_count = self.policies.get(policy_key)

		if action == 'add':
			if to_mysql:
				self.insert_into_conns(pod, reqid, ts, vrf)

			system("ip link add %s type dummy" % intf)
			system("ip link set dev %s master VRF%d" % (intf, vrf))
			system("ip add add %s dev %s" % (prefix, intf));
			system("ip link set dev %s up" % intf);

			if policy_ref_count == None:
				self.add_policy(bsid, prefix, vrf, pod)
				self.policies[policy_key] = 0
			self.policies[policy_key] += 1

		else:
			if policy_ref_count == None:
				return
			assert(policy_ref_count > 0)

			if to_mysql:
				self.delete_from_conns(pod, reqid)

			system("ip link del %s" % intf);

			self.policies[policy_key] -= 1
			if self.policies[policy_key] == 0:
				self.policies.pop(policy_key)
				self.del_policy(bsid, prefix, vrf)


	def __init__(self, args):
		self.connect_vpp(load_json_api_files())
		self.connect_mysql(args.mysql_server, args.mysql_user, args.mysql_password)

		self.nats_server = args.nats_server

		self.policies = {}

		mysql_cursor = self.mysql_execute("select * from conns")
		while True:
			row = mysql_cursor.fetchone()
			if row == None:
				break
			assert(len(row) == 4)
			pod = int(row[0])
			reqid = int(row[1])
			ts = str(row[2])
			vrf = int(row[3])
			self.process_updown(False, "add", reqid, ts, vrf, pod)


	def vpp_test(self, msg):
		bsid = "2999:%d:%d:1::" % (1, 12)
		segs = [None] * 16
		segs[0] = "2aaa:%d:%d:1::" % (1, 12)
		prefix = ipaddress.ip_network("48.0.0.0/8")

		system("ip link del VRF%d" % 1)
		system("ip link add dev VRF%d type vrf table %d" % (1, 1))

		self.vpp.api.sr_policy_add(bsid_addr = bsid,
				weight = 1,
				is_encap = 1,
				sids = { "num_sids": 1, "sids": segs })

		self.vpp.api.sr_steering_add_del(is_del = 0,
			bsid_addr = bsid,
			table_id = 1,
			prefix = { "address": prefix.network_address, "len": prefix.prefixlen },
			traffic_type = SR_STEER_IPV4)


	async def process_message(self, msg):
		data = msg.data.decode("utf-8")
		print("process: %s: %s" % (msg.subject, data))
		args = data.split(' ')
		if msg.subject == "shutdown":
			pod = int(args[0])
			self.process_shutdown(pod)
		elif msg.subject == "updown":
			action = args[0]
			reqid = int(args[1])
			ts = args[2]
			vrf = int(args[3])
			pod = int(args[4])
			self.process_updown(True, action, reqid, ts, vrf, pod)


	async def start(self):
		nc = await nats.connect(self.nats_server)

		await nc.subscribe("updown", "workers", self.process_message)
		await nc.subscribe("shutdown", "", self.process_message)

		while True:
			try:
				await nc.flush(1)
			except nats.errors.TimeoutError:
				pass
			except Exception:
				print(traceback.format_exc())
				print(sys.exc_info()[2])

		await nc.close()


if __name__ == '__main__':
	ap = argparse.ArgumentParser()
	ap.add_argument("--nats-server", metavar="host", type=str, default="localhost",
			help="Specify nats server host")

	ap.add_argument("--mysql-server", metavar="host", type=str, default="localhost",
			help="Specify mysql server host")

	ap.add_argument("--mysql-user", metavar="user", type=str, default="mysql",
			help="Specify mysql user")

	ap.add_argument("--mysql-password", metavar="password", type=str, default="",
			help="Specify mysql user password")

	args = ap.parse_args()

	server = Server(args)

	asyncio.run(server.start())
