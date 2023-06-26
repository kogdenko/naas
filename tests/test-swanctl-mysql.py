#!/usr/bin/python
# pip3 install mysql-connector-python

import time
import ipaddress
import mysql.connector

KIND_LOCAL = 0
KIND_REMOTE = 1

# 12[CFG] vici message size 2424108 exceeds maximum size of 524288, discarded
# update traffic_selectors set start_addr = X'01010101'  end_addr = X'02010101' where id = 15990;
class Generator:
	def __init__(self):
		self.mysql_conn = mysql.connector.connect(user="root", database="swanctl")
		self.secret = "bfe364c58f4b2d9bf08f8a820b6a3f806ad60c5d9ddb58cb"
		self.id2sql = [ None, "31", "32", "33", "34", "35", "36", "37", "38", "39", # 0-9
			"3130", "3131", "3132", "3133", "3134", "3135", "3136", "3137", "3138", "3139", #10-19
			"3230", "3231", "3232", "3233", "3234", "3235", "3236", "3237", "3238", "3239", #20-29
			]


	def execute(self, cmd, *args):
		try:
			mysql_cursor = self.mysql_conn.cursor(buffered = True)
			mysql_cursor.execute(cmd, *args);
		except mysql.connector.errors.ProgrammingError as exc:
			raise RuntimeError("mysql query '%s' failed" % cmd) from exc
		return mysql_cursor


	def commit(self):
		self.mysql_conn.commit()


	def add_shared_secret_identity(self, secret_id, identity_id):
		self.execute(("insert into shared_secret_identity (shared_secret, identity) values (%d, %d)" % 
				(secret_id, identity_id)))
		self.commit()


	def add_traffic_selector(self, start_addr, end_addr):
		c = self.execute(("insert into traffic_selectors (type, start_addr, end_addr) "
				"values (7, X'%.8x', X'%.8x')" % (int(start_addr), int(end_addr))))
		self.commit()
		return c.lastrowid


	def add_child_config_traffic_selector(self, child_id, ts_id, kind):
		self.execute("insert into child_config_traffic_selector (child_cfg, traffic_selector, kind ) "
				"values (%d, %d, %d)" % (child_id, ts_id, kind))
		self.commit()


	def add_ike_config(self, local, remote):
		c = self.execute("insert into ike_configs (local, remote) values ('%s', '%s')" % (local, remote))
		self.commit()
		return c.lastrowid


	def add_identitiy(self, vrf):
		c = self.execute("insert into identities (type, data) values (11, X'%s')" % self.id2sql[vrf])
		self.commit()
		return c.lastrowid


	def add_identitiy_ip(self, ip):
		c = self.execute("insert into identities (type, data) values (1, X'%.8x')" % int(ip))
		self.commit()
		return c.lastrowid


	def add_shared_secret(self):
		c = self.execute("insert into shared_secrets (type, data) values (1, X'%s')" % self.secret)
		self.commit()
		return c.lastrowid


	def add_peer_config(self, name, ike_id, local_id, remote_id):
		c = self.execute(("insert into peer_configs (name, ike_cfg, local_id, remote_id, auth_method, mobike)"
				"values ('%s', %d, %d, %d, 2, 0)" % (name, ike_id, local_id, remote_id)))
		self.commit()
		return c.lastrowid


	def add_child_config(self, name):
		c = self.execute(("insert into child_configs (name, updown) "
				"values ('%s', '/usr/local/libexec/ipsec/_updown iptables')" % name))
		self.commit()
		return c.lastrowid

	def add_peer_config_child_config(self, peer_id, child_id):
		self.execute("insert into peer_config_child_config (peer_cfg, child_cfg) values (%d, %d)" %
				(peer_id, child_id))
		self.commit()


	def helloworld(self):
		local_id = self.add_identitiy(13)
		remote_id = self.add_identitiy(12)
		secret_id = self.add_shared_secret()

		self.add_shared_secret_identity(secret_id, local_id)
		self.add_shared_secret_identity(secret_id, remote_id)

		ike_id = self.add_ike_config(ipaddress.ip_address("192.168.31.11"),
				ipaddress.ip_address("0.0.0.0"))

		peer_id = self.add_peer_config("0", ike_id, local_id, remote_id)

		child_id = self.add_child_config("net-net")

		self.add_peer_config_child_config(peer_id, child_id)

		start_addr = ipaddress.ip_address("0.0.0.0")
		end_addr = ipaddress.ip_address("255.255.255.255")
		local_ts_id = self.add_traffic_selector(start_addr, end_addr)
		remote_ts_id = self.add_traffic_selector(start_addr, end_addr)

		self.add_child_config_traffic_selector(child_id, local_ts_id, KIND_LOCAL)
		self.add_child_config_traffic_selector(child_id, remote_ts_id, KIND_REMOTE)


	def big_simple(self, n):
		local_id = self.add_identitiy(13)
		remote_id = self.add_identitiy(12)
		secret_id = self.add_shared_secret()

		self.add_shared_secret_identity(secret_id, local_id)
		self.add_shared_secret_identity(secret_id, remote_id)

		ike_id = self.add_ike_config(ipaddress.ip_address("192.168.31.11"),
				ipaddress.ip_address("0.0.0.0"))

		child_id = self.add_child_config("net-net")

		start_addr = ipaddress.ip_address("0.0.0.0")
		end_addr = ipaddress.ip_address("255.255.255.255")
		local_ts_id = self.add_traffic_selector(start_addr, end_addr)
		remote_ts_id = self.add_traffic_selector(start_addr, end_addr)

		self.add_child_config_traffic_selector(child_id, local_ts_id, KIND_LOCAL)
		self.add_child_config_traffic_selector(child_id, remote_ts_id, KIND_REMOTE)

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
		local_id = self.add_identitiy(index)
		remote_id = self.add_identitiy_ip(self.local_ip)
		secret_id = self.add_shared_secret()
	
		self.add_shared_secret_identity(secret_id, local_id)
		self.add_shared_secret_identity(secret_id, remote_id)

		self.local_ip += 1
		self.remote_ip += 1
		ike_id = self.add_ike_config(self.local_ip, self.remote_ip)
		client_name = "c_" + str(index)
		peer_id = self.add_peer_config(client_name, ike_id, local_id, remote_id)

		for tunnel_index in range(0, n_tunnels):
			child_name = client_name + "_" + str(tunnel_index)
			child_id = self.add_child_config(child_name)
			self.add_peer_config_child_config(peer_id, child_id)

			for i in range(0, n_traffic_selectors):
				local_ts_id = self.add_traffic_selector(self.local_ts, self.local_ts + 2)
				self.add_child_config_traffic_selector(child_id, local_ts_id, KIND_LOCAL)
				self.progress_traffic_selector(child_name, self.local_ts, local_ts_id)
				self.local_ts += 3

			for i in range(0, 10):
				remote_ts_id = self.add_traffic_selector(self.remote_ts, self.remote_ts + 2)
				self.remote_ts += 3
				self.add_child_config_traffic_selector(child_id, remote_ts_id, KIND_REMOTE)


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
#	gen.helloworld()
#	gen.big_simple(100000)
	gen.real_world(20, 20, 30)




if __name__ == '__main__':
	main()
