import ipaddress
import mysql.connector


TS_LOCAL = 0
TS_REMOTE = 1

ID_ANY = 0
ID_IPV4_ADDR = 1
ID_FQDN = 2
ID_KEY_ID = 11


class MySql:
	def __init__(self):
		self.mysql_conn = mysql.connector.connect(user="root", database="swanctl")
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
		self.execute(("insert ignore into shared_secret_identity (shared_secret, identity) "
				"values (%d, %d)" % 
				(secret_id, identity_id)))
		self.commit()


	def add_traffic_selector(self, child_id, kind, start_addr, end_addr):
		c = self.execute(("insert into traffic_selectors (type, start_addr, end_addr) "
				"values (7, X'%.8x', X'%.8x')" % (int(start_addr), int(end_addr))))
		self.commit()
		ts_id = c.lastrowid

		self.execute("insert into child_config_traffic_selector (child_cfg, traffic_selector, kind) "
				"values (%d, %d, %d)" % (child_id, ts_id, kind))
		self.commit()


	def del_traffic_selector(self, child_id, ts_id):
		self.execute("delete from traffic_selectors where id=%d" % ts_id)
		self.execute(("delete from child_config_traffic_selector "
				"where child_cfg = %d and traffic_selector = %d" % (child_id, ts_id)))
		self.commit()


	def add_ike_config(self, local, remote):
		c = self.execute("insert into ike_configs (local, remote) values ('%s', '%s')" % (local, remote))
		self.commit()
		return c.lastrowid


	# ID_KEY_ID
	def id_key_id_2_sql(self, key_id):
		return ("X'%s'" % self.id2sql[key_id])


	# ID_FQDN
	def id_fqdn_2_sql(self, fqdn):
		data = "X"
		for x in str.encode(s):
			data += ("%.2x" % x)
		return data

	# ID_IPV4_ADDR
	def id_ipv4_addr_2_sql(self, ipv4_addr):
		return "X'%.8x'" % int(ip)


	def add_identity(self, identity_type, identity):
		if identity_type == ID_ANY:
			data = "'%any'"
		elif identity_type == ID_KEY_ID:
			data =  self.id_key_id_2_sql(identity)
		elif identity_type == ID_FQDN:
			data = self.id_ipv4_addr_2_sql(identity)
		elif identity_type == ID_IPV4_ADDR:
			data = self.id_ipv4_addr_2_sql(identity)
		else:
			assert(0)

		c = self.execute(("select id from identities where type = %d and data = %s"
				% (identity_type, data)))
		row = c.fetchone()
		if row == None:
			c = self.execute(("insert into identities (type, data) "
					"values (%d, %s)" % (identity_type, data)))
			self.commit()
			rowid = c.lastrowid
		else:
			rowid = int(row[0])

		assert(rowid > 0)
		return rowid


	def add_identity_ipv4_addr(self, ipv4_addr):
		return self.add_identity_raw(ID_IPV4_ADDR, self.id_ipv4_addr_2_sql(ipv4_addr))


	def add_shared_secret(self, secret):
		c = self.execute("insert into shared_secrets (type, data) values (1, X'%s')" % secret)
		self.commit()
		return c.lastrowid


	def add_peer_config(self, name, ike_id, local_id, remote_id):
		c = self.execute(("insert into peer_configs (name, ike_cfg, local_id, remote_id, auth_method, mobike)"
				"values ('%s', %d, %d, %d, 2, 0)" % (name, ike_id, local_id, remote_id)))
		self.commit()
		return c.lastrowid


	def add_child_config(self, name, updown):
		c = self.execute(("insert into child_configs (name, updown) "
				"values ('%s', '%s')" % (name, updown)))
		self.commit()
		return c.lastrowid


	def add_peer_config_child_config(self, peer_id, child_id):
		self.execute("insert into peer_config_child_config (peer_cfg, child_cfg) values (%d, %d)" %
				(peer_id, child_id))
		self.commit()

