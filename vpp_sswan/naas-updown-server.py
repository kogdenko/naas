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
from syslog  import syslog, LOG_ERR, LOG_INFO
from vpp_papi import VPPApiJSONFiles, vpp_papi


VPP_JSON_DIR = '/usr/share/vpp/api/core/'
API_FILE_SUFFIX = '*.api.json'
SR_STEER_IPV4 = 4


def print_log(priority, s):
	syslog(priority, s)
	print(s)


def print_err():
	print_log(LOG_ERR, traceback.format_exc())
	print_log(LOG_ERR, sys.exc_info()[2])


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
		print_log(LOG_INFO, log)

	return rc


def load_json_api_files(json_dir=VPP_JSON_DIR, suffix=API_FILE_SUFFIX):
	jsonfiles = []
	for root, dirnames, filenames in os.walk(json_dir):
		for filename in fnmatch.filter(filenames, suffix):
			jsonfiles.append(os.path.join(json_dir, filename))
	return jsonfiles


class Server:
	def connect_vpp(self, vpp_api_socket, jsonfiles):
		self.vpp = vpp_papi.VPPApiClient(apifiles=jsonfiles,
				server_address=vpp_api_socket)
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
				"vrf int,"
				"reqid INT,"
				"ts varchar(63),"
				"primary key(pod, vrf, reqid, ts)"
				")")


	# nats --server 192.168.122.1 pub shutdown "1"
	def process_pod_shutdown(self, pod):
		mysql_cursor = self.mysql_execute("select * from conns where pod = %d" % pod)
		while True:
			rows = mysql_cursor.fetchone()
			if rows == None:
				break
			assert(len(rows) == 4)
			pod = int(rows[0])
			vrf = int(rows[1])
			reqid = int(rows[2])
			ts = str(rows[3])
			self.process_tunnel_updown(False, True, pod, vrf, reqid, ts)

		self.mysql_execute("delete from conns where pod = %d" % (pod))
		self.mysql_conn.commit()


	def add_policy(self, bsid, vrf, prefix):
		self.vpp.api.sr_steering_add_del(is_del = 0,
			bsid_addr = bsid,
			table_id = vrf,
			prefix = { "address": prefix.network_address, "len": prefix.prefixlen },
			traffic_type = SR_STEER_IPV4)


	def del_policy(self, bsid, vrf, prefix):
		self.vpp.api.sr_steering_add_del(is_del = 1,
				bsid_addr = bsid,
				table_id = vrf,
				prefix = { "address": prefix.network_address, "len": prefix.prefixlen },
				traffic_type = SR_STEER_IPV4)


	def insert_into_db(self, pod, vrf, reqid, ts):
		mysql_cmd = ("insert into conns (pod, vrf, reqid, ts) values (%d, %d, %d, \"%s\")"
				% (pod, vrf, reqid, ts))
		self.mysql_execute(mysql_cmd)
		self.mysql_conn.commit()


	def delete_from_db(self, pod, vrf, reqid, ts):
		mysql_cmd = ("delete from conns where pod = %d and vrf = %d and reqid = %d and ts = \"%s\""
				% (pod, vrf, reqid, ts))
		self.mysql_execute(mysql_cmd)
		self.mysql_conn.commit()


	def create_bsid(self, pod, vrf):
		return "2999:%d:%d:1::" % (pod, vrf)


	# nats --server 192.168.122.1 pub tunnel-up "1 12 1 48.0.0.0/24"
	def process_tunnel_updown(self, is_up, commit, pod, vrf, reqid, ts):
		prefix = ipaddress.ip_network(ts)
		prefix.network_address += 1

		bsid = self.create_bsid(pod, vrf)

		conn = str(pod) + "_" + str(vrf) + "_" + str(reqid) + "_" + str(ts)
		conn_ref_count = self.conns.get(conn)

		intf = "p" + str(pod) + "-ipsec" + str(reqid) + "-" + str(vrf)
		intf_ref_count = self.intfs.get(intf)

		if is_up:
			if conn_ref_count != None:
				return
			self.conns[conn] = 1

			if commit:
				self.insert_into_db(pod, vrf, reqid, ts)

			if intf_ref_count == None:
				system("ip link add %s type dummy" % intf)
				system("ip link set dev %s master VRF%d" % (intf, vrf))
				system("ip link set dev %s up" % intf);
				self.intfs[intf] = 0
			self.intfs[intf] += 1

			system("ip addr add %s dev %s" % (prefix, intf));
			self.add_policy(bsid, vrf, prefix)
				
		else:
			if conn_ref_count == None:
				return
			del self.conns[conn]

			if commit:
				self.delete_from_db(pod, vrf, reqid, ts)

			self.del_policy(bsid, vrf, prefix)
			system("ip addr del %s dev %s" % (prefix, intf))

			assert(intf_ref_count != None)
			self.intfs[intf] -= 1
			if self.intfs[intf] == 0:
				del self.intfs[intf]
				system("ip link del %s" % intf);


	def __init__(self, args):
		self.connect_vpp(args.vpp_api_socket, load_json_api_files())
		self.connect_mysql(args.mysql_server, args.mysql_user, args.mysql_password)

		self.nats_server = args.nats_server
		self.conns = {}
		self.intfs = {}


	def restore(self):
		mysql_cursor = self.mysql_execute("select * from conns")
		while True:
			rows = mysql_cursor.fetchone()
			if rows == None:
				break
			assert(len(rows) == 4)
			pod = int(rows[0])
			vrf = int(rows[1])
			reqid = int(rows[2])
			ts = str(rows[3])
			self.process_tunnel_updown(True, False, pod, vrf, reqid, ts)


	def configure(self, pod, vrf):
		bsid = self.create_bsid(pod, vrf)
		segs = [None] * 16
		segs[0] = "2aaa:%d:%d:1::" % (pod, vrf)

		system("ip link del VRF%d" % vrf)
		system("ip link add dev VRF%d type vrf table %d" % (vrf, vrf))

		self.vpp.api.sr_policy_add(bsid_addr = bsid,
				weight = 1,
				is_encap = 1,
				sids = { "num_sids": 1, "sids": segs })


	async def process_message(self, msg):
		data = msg.data.decode("utf-8")
		print_log(LOG_INFO, "process: %s: %s" % (msg.subject, data))
		args = data.split(' ')
		if msg.subject == "pod-shutdown":
			pod = int(args[0])
			self.process_pod_shutdown(pod)
		elif msg.subject == "tunnel-up":
			pod = int(args[0])
			vrf = int(args[1])
			reqid = int(args[2])
			ts = args[3]
			self.process_tunnel_updown(True, True, pod, vrf, reqid, ts)
		elif msg.subject == "tunnel-down":
			pod = int(args[0])
			vrf = int(args[1])
			reqid = int(args[2])
			ts = args[3]
			self.process_tunnel_updown(False, True, pod, vrf, reqid, ts)


	async def run(self):
		nc = await nats.connect(self.nats_server)

		await nc.subscribe("tunnel-up", "workers", self.process_message)
		await nc.subscribe("tunnel-down", "workers", self.process_message)
		await nc.subscribe("pod-shutdown", "", self.process_message)


def main():
	ap = argparse.ArgumentParser()
	ap.add_argument("--nats-server", metavar="host", type=str, default="localhost",
			help="Specify nats server host")

	ap.add_argument("--mysql-server", metavar="host", type=str, default="localhost",
			help="Specify mysql server host")

	ap.add_argument("--mysql-user", metavar="user", type=str, default="mysql",
			help="Specify mysql user")

	ap.add_argument("--mysql-password", metavar="password", type=str, default="",
			help="Specify mysql user password")

	ap.add_argument("--vpp-api-socket", metavar="path", type=str, default="/run/vpp/api.sock",
			help="Specify VPP api socket")

	ap.add_argument("--configure", action='store_true', help="Configure ip tables/policies")

	args = ap.parse_args()

	server = Server(args)

	# Debug only
	if args.configure:
		server.configure(10, 12)
		return

	server.restore()
	print_log(LOG_INFO, "Listening incoming messages...")

	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)
	loop.run_until_complete(server.run())
	try:
		loop.run_forever()
	finally:
		loop.close()


if __name__ == '__main__':
	main()
