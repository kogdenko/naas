#!/usr/bin/python
# pip3 install mysql-connector-python

import os
import sys
import time
import ipaddress
import mysql.connector

sys.path.append(os.path.expanduser(os.path.dirname(os.path.realpath(__file__))) + "/..")
from naaspy import swanctl


# 12[CFG] vici message size 2424108 exceeds maximum size of 524288, discarded
# update traffic_selectors set start_addr = X'01010101'  end_addr = X'02010101' where id = 15990;
class Generator(swanctl.MySql):
	def __init__(self):
		swanctl.MySql.__init__(self)
		self.secret = "bfe364c58f4b2d9bf08f8a820b6a3f806ad60c5d9ddb58cb"


	def helloworld(self):
		local_id = self.add_identity(swanctl.ID_FQDN, "magnit.ru")
		remote_id = self.add_identity(swanctl.ID_KEY_ID, 0)
		secret_id = self.add_shared_secret(self.secret)

		self.add_shared_secret_identity(secret_id, local_id)
		self.add_shared_secret_identity(secret_id, remote_id)

		ip_zero = ipaddress.ip_address("0.0.0.0")
		ike_id = self.add_ike_config(ip_zero, ip_zero);

		peer_id = self.add_peer_config("0", ike_id, local_id, remote_id)

		child_id = self.add_child_config("net-net", "naas-updown.sh")

		self.add_peer_config_child_config(peer_id, child_id)

		ts = swanctl.TrafficSelector()
		ts.deserialize("16.0.0.0/8")
		self.add_traffic_selector(child_id, swanctl.TS_LOCAL, ts.start_addr, ts.end_addr)

		ts.deserialize("48.0.0.0/8")
		self.add_traffic_selector(child_id, swanctl.TS_REMOTE, ts.start_addr, ts.end_addr)


	def big_simple(self, n):
		local_id = self.add_identity(swanctl.ID_KEY_ID, 13)
		remote_id = self.add_identity(swanctl.ID_KEY_ID, 12)
		secret_id = self.add_shared_secret(self.secret)

		self.add_shared_secret_identity(secret_id, local_id)
		self.add_shared_secret_identity(secret_id, remote_id)

		ike_id = self.add_ike_config(ipaddress.ip_address("192.168.31.11"),
				ipaddress.ip_address("0.0.0.0"))

		child_id = self.add_child_config("net-net", "naas-updown.sh")

		start_addr = ipaddress.ip_address("0.0.0.0")
		end_addr = ipaddress.ip_address("255.255.255.255")
		self.add_traffic_selector(child_id, swanctl.TS_LOCAL, start_addr, end_addr)
		self.add_traffic_selector(child_id, swanctl.TS_REMOTE, start_addr, end_addr)

		for i in range(0, n):	
			peer_id = self.add_peer_config(str(i), ike_id, local_id, remote_id)
			self.add_peer_config_child_config(peer_id, child_id)


	def progress_traffic_selector(self, child_name, ts, ts_id):
		self.traffic_selectors += 1
		progress = int(self.traffic_selectors * 100 / self.traffic_selectors_all)
		if progress > self.progress:
			units = "Sec"
			self.progress = progress
			t = time.time()
			dt = t - self.progress_time
			self.progress_time = t
			dt *= (100 - progress)
			if dt > 60:
				dt /= 60
				units = "Min"
				if dt > 60:
					dt /= 60
					units = "Hours"
					if dt > 24:
						dt /= 24
						units = "Days"
			print(("%d%%, approximate time: %d %s; tunnel=%s, ts=%s, ts_id=%d" %
					(progress, dt, units, child_name, ts, ts_id)))
		

	def real_world_client(self, index, n_tunnels, n_traffic_selectors):
		local_id = self.add_identity(swanctl.ID_KEY_ID, index)
		remote_id = self.add_identity(swanctl.ID_IPV4_ADDR, self.local_ip)
		secret_id = self.add_shared_secret(self.secret)
	
		self.add_shared_secret_identity(secret_id, local_id)
		self.add_shared_secret_identity(secret_id, remote_id)

		self.local_ip += 1
		self.remote_ip += 1
		ike_id = self.add_ike_config(self.local_ip, self.remote_ip)
		client_name = "c_" + str(index)
		peer_id = self.add_peer_config(client_name, ike_id, local_id, remote_id)

		for tunnel_index in range(0, n_tunnels):
			child_name = client_name + "_" + str(tunnel_index)
			child_id = self.add_child_config(child_name, "naas-updown.sh")
			self.add_peer_config_child_config(peer_id, child_id)

			for i in range(0, n_traffic_selectors):
				local_ts_id = self.add_traffic_selector(child_id, swanctl.TS_LOCAL,
						self.local_ts, self.local_ts + 2)
				self.progress_traffic_selector(child_name, self.local_ts, local_ts_id)
				self.local_ts += 3

			for i in range(0, 10):
				self.add_traffic_selector(child_id, swanctl.TS_REMOTE,
						self.remote_ts, self.remote_ts + 2)
				self.remote_ts += 3


	def real_world(self, n_clients, n_tunnels_per_client, n_traffic_selectors):
		self.local_ip = ipaddress.ip_address("192.168.31.11")
		self.remote_ip = ipaddress.ip_address("192.168.51.11")
		self.local_ts = ipaddress.ip_address("10.1.1.1")
		self.remote_ts = ipaddress.ip_address("20.1.1.1")


		self.progress_time = time.time()
		self.progress = 0
		self.traffic_selectors = 0;
		self.traffic_selectors_all = n_clients * n_tunnels_per_client * n_traffic_selectors
		for i in range(0, n_clients):
			self.real_world_client(i + 1, n_tunnels_per_client, n_traffic_selectors)
		


def main():
	gen = Generator()
	gen.connect()
	gen.helloworld()
#	gen.big_simple(100000)
#	gen.real_world(2, 20, 30)


if __name__ == '__main__':
	main()
