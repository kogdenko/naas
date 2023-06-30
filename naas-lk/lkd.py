#!/usr/bin/python
import os
import sys
import math
import ipaddress
import threading
import hashlib
import secrets
import mysql.connector


sys.path.append(os.path.expanduser(os.path.dirname(os.path.realpath(__file__))) + "/..")
from naaspy import swanctl

from flask import Flask, jsonify, abort, request, make_response 


class Cookie:
	pass


cookies = {}


def is_authorized(request):
	if not 'user' in request.json:
		return False

	user = request.json['user']
	token = request.cookies.get("auth")
	if not token:
		return None

	cookie = cookies.get(user)
	if not cookie:
		return None

	print(token)
	print(cookie.tokens)
	if token in cookie.tokens:
		return cookie.vrf
	else:
		return None
	

class TrafficSelector:
	def __init__(self):
		self.id = None


	def deserialize(self, s):
		splited = s.split('-')
		if len(splited) == 2:
			self.start_addr = ipaddress.ip_address(splited[0])
			self.end_addr = ipaddress.ip_address(splited[1])
			if int(self.end_addr) < int(self.start_addr):
				raise ValueError("'%s': does not appear to be an traffic selector" % s)
		subnet = ipaddress.ip_network(s)
		self.start_addr = subnet.network_address
		self.end_addr = subnet.network_address + (subnet.num_addresses - 1)


	def __eq__(self, other):
		return (self.start_addr == other.start_addr and self.end_addr == other.end_addr)


	def __str__(self):
		num_addresses = int(self.end_addr) - int(self.start_addr) + 1
		n = math.log(num_addresses, 2)
		if n.is_integer():
			prefix_len = 32 - int(n)
			return str(self.start_addr) + "/" + str(prefix_len)
		else:
			return str(self.start_addr) + "-" + str(self.end_addr)


	def __repr__(self):
		return self.__str__()


def serialize_traffic_selectors(traffic_selectors):
	data = []
	for ts in traffic_selectors:
		data.append(str(ts))
	return data 


class UserData:
	pass


class Backend(Flask, swanctl.MySql):
	def __init__(self):
		Flask.__init__(self, __name__)
		swanctl.MySql.__init__(self)
		self.lock = threading.Lock()


	def connect(self, host, user, password):
		swanctl.MySql.connect(self, host, user, password)
		self.auth_db_mysql = mysql.connector.connect(host=host, user=user,
				password=password, database="auth2")


	def auth_execute(self, cmd):
		return swanctl.mysql_execute(self.auth_db_mysql, cmd)


	def create_traffic_selectors(self, list_of_strings):
		traffic_selectors = []
		for s in list_of_strings:
			ts = TrafficSelector()
			ts.deserialize(s)
			traffic_selectors.append(ts)
		return traffic_selectors


	def get_traffic_selectors(self, child_id, kind=None):
		cmd = ("select traffic_selector from child_config_traffic_selector "
				"where child_cfg = %d" % child_id)

		if kind != None:
			cmd += " and kind = %d" % kind

		c = self.execute(cmd)

		traffic_selectors = []
		while True:
			row = c.fetchone()
			if row == None:
				break
			ts = TrafficSelector()
			ts.id = int(row[0])
			traffic_selectors.append(ts)

		for ts in traffic_selectors:
			c = self.execute(("select start_addr, end_addr from traffic_selectors "
					"where id = %d" % (ts.id)))
			row = c.fetchone()
			ts.start_addr = ipaddress.ip_address(int.from_bytes(row[0], "big"))
			ts.end_addr = ipaddress.ip_address(int.from_bytes(row[1], "big"))

		return traffic_selectors


	def add_traffic_selectors(self, child_id, kind, traffic_selectors):
		for ts in traffic_selectors:
			ts.id = self.add_traffic_selector(child_id, kind,
					ts.start_addr, ts.end_addr)


	def del_traffic_selectors(self, child_id, traffic_selectors):
		for ts in traffic_selectors:
			self.del_traffic_selector(child_id, ts.id)


	def config_mod_traffic_selectors(self, child_id, kind, traffic_selectors):
		old_traffic_selectors = self.get_traffic_selectors(child_id, kind)
		for ts in old_traffic_selectors:
			if ts in traffic_selectors:
				traffic_selectors.remove(ts)
				old_traffic_selectors.remove(ts)

		self.add_traffic_selectors(child_id, kind, traffic_selectors)
		self.del_traffic_selectors(child_id, old_traffic_selectors)


	def config_del_traffic_selectors(self, child_id):
		traffic_selectors = self.get_traffic_selectors(child_id)
		self.del_traffic_selectors(child_id, traffic_selectors)


	def get_child_config_name(self, child_id):
		c = self.execute("select name from child_configs where id = %d" % child_id)
		row = c.fetchone()
		return row[0]


	def config_add_config(self, config_name, peer_id, local_ts, remote_ts):
		child_id = self.add_child_config(config_name, "naas-updown.sh")
		self.add_peer_config_child_config(peer_id, child_id)

		self.add_traffic_selectors(child_id, swanctl.TS_LOCAL, local_ts)
		self.add_traffic_selectors(child_id, swanctl.TS_REMOTE, remote_ts)

		return 200


	def config_add_ike(self, user_name, config_name, local_id, remote_id,
			mobike, secret, local_ts, remote_ts):
		ip_zero = ipaddress.ip_address("0.0.0.0")
		ike_id = self.add_ike_config(ip_zero, ip_zero)
		peer_id = self.add_peer_config(user_name, ike_id, local_id, remote_id)

		return self.config_add_config(config_name, peer_id, local_ts, remote_ts)


	def select_user(self, user_name):
		c = self.execute(("select id, ike_cfg, local_id, remote_id, mobike "
				"from peer_configs where name = '%s'" %
				user_name))
		row = c.fetchone()
		if row == None:
			return None
		
		user = UserData()
		user.peer_id = int(row[0])
		user.ike_id = int(row[1])
		user.local_id = int(row[2])
		user.remote_id = int(row[3])
		user.mobike = int(row[4])
		c = self.execute(("select child_cfg from peer_config_child_config where peer_cfg = %d"
				% user.peer_id))
		user.config_ids = []
		while True:
			row = c.fetchone()
			if row == None:
				break
			user.config_ids.append(int(row[0]))

		return user


	def config_mod(self, user_name, vrf, config_name, mobike, secret, local_ts, remote_ts):
		local_id = self.add_identity(swanctl.ID_ANY, None)
		remote_id = self.add_identity(swanctl.ID_KEY_ID, vrf)
		secret_id = self.add_shared_secret(secret)

		self.add_shared_secret_identity(secret_id, local_id)
		self.add_shared_secret_identity(secret_id, remote_id)

		user = self.select_user(user_name)
		if user == None:
			return self.config_add_ike(user_name, config_name,
					local_id, remote_id, secret_id,
					mobike, local_ts, remote_ts)

		if (local_id != user.local_id or remote_id != user.remote_id or
				mobike != user.mobike):
			self.execute(("update peer_configs set local_id=%d, remote_id=%d, mobike=%d "
				"where id = %d" % (local_id, remote_id, mobike, user.peer_id)))
			self.commit()

		for child_id in user.config_ids:
			if config_name == self.get_child_config_name(child_id):
				self.config_mod_traffic_selectors(child_id,
						swanctl.TS_LOCAL, local_ts)
				self.config_mod_traffic_selectors(child_id,
						swanctl.TS_REMOTE, remote_ts)
				return 200

		self.config_add_config(config_name, user.peer_id, local_ts, remote_ts)
		return 200

	
	def config_del_child(self, child_id):
		self.config_del_traffic_selectors(child_id)
		self.execute(("delete from peer_config_child_config where child_cfg = %d"
				% child_id))
		self.execute("delete from child_configs where id = %d" % child_id)
		self.commit()


	def config_del(self, user_name, config_name):
		user = self.select_user(user_name)
		if user == None:
			return 404

		code = 404
		for child_id in user.config_ids:
			if config_name == self.get_child_config_name(child_id):
				code = 200
				self.config_del_child(child_id)
				user.config_ids.remove(child_id)
				break

		if not len(user.config_ids):
			self.execute("delete from peer_configs where id = %d" % user.peer_id)
			self.execute("delete from ike_configs where id = %d" % user.ike_id)
			self.commit()

		return code


	def config_get(self, user_name, config_name):
		user = self.select_user(user_name)
		if user == None:
			return 404, {}

		config_id = None
		for child_id in user.config_ids:
			if config_name == self.get_child_config_name(child_id):
				config_id = child_id
		if not config_id:
			return 404

		local_ts = self.get_traffic_selectors(config_id, swanctl.TS_LOCAL)
		remote_ts = self.get_traffic_selectors(config_id, swanctl.TS_REMOTE)

		secret = self.get_shared_secret_by_identity_id(user.local_id)

		result = {
			"user": user_name,
			"config": config_name,
			"mobike": user.mobike,
			"secret": secret,
			"local_ts": serialize_traffic_selectors(local_ts),
			"remote_ts": serialize_traffic_selectors(remote_ts),
		}

		return 200, result

app = Backend()

# curl  -i -H "Content-Type: application/json" -X POST -d @config_mod.json 127.0.0.1:5000/api/v1.0/config/mod
@app.route('/api/v1.0/config/mod', methods=['POST'])
def config_mod():
	if not request.json:
		abort(400)
	if not 'user' in request.json:
		abort(400)
	if not 'config' in request.json:
		abort(400)
	if not 'mobike' in request.json:
		mobike = False
	else:
		mobike = bool(request.json['mobike'])

	vrf = is_authorized(request)
	if not vrf:
		return jsonify({}), 401

	user_name = request.json['user']
	config_name = request.json['config']
	secret = request.json['secret']
	local_ts = app.create_traffic_selectors(request.json['local_ts'])
	if not len(local_ts):
		abort(400)
	remote_ts = app.create_traffic_selectors(request.json['remote_ts'])
	if not len(remote_ts):
		abort(400)

	with app.lock:
		code = app.config_mod(user_name, vrf, config_name, mobike, secret,
				local_ts, remote_ts)

	return jsonify({}), code


@app.route('/api/v1.0/config/del', methods=['POST'])
def config_del():
	if not request.json:
		abort(400)
	if not 'user' in request.json:
		abort(400)
	if not 'config' in request.json:
		abort(400)

	user_name = request.json['user']
	config_name = request.json['config']

	if not is_authorized(request):
		return jsonify({}), 401

	with app.lock:
		code = app.config_del(user_name, config_name)

	return jsonify({}), code


@app.route('/api/v1.0/config/get', methods=['GET'])
def config_get():
	if not request.json:
		abort(400)
	if not 'user' in request.json:
		abort(400)
	if not 'config' in request.json:
		abort(400)

	if not is_authorized(request):
		return jsonify({}), 401

	user_name = request.json['user']
	config_name = request.json['config']

	with app.lock:
		code, data = app.config_get(user_name, config_name)

	return jsonify(data), code


@app.route('/api/v1.0/auth', methods=['GET'])
def auth():
	if not request.json:
		abort(400)
	if not 'user' in request.json:
		abort(400)
	if not 'password' in request.json:
		abort(400)

	user = request.json['user']
	password_md5 = hashlib.md5(request.json['password'].encode())
	password = ''.join("%.2x" % i for i in password_md5.digest())

	c = app.auth_execute("select password, vrf from user where name = '%s'" % user)
	row = c.fetchone()
	if row == None:
		abort(401)

	if row[0] != password:
		abort(401)

	vrf = int(row[1])

	token = ''.join("%.2x" % i for i in secrets.token_bytes(32))
	resp = make_response()

	cookie = cookies.get(user)
	if cookie == None:
		cookie = Cookie()
		cookie.user = user
		cookie.vrf = vrf
		cookie.tokens = []
		cookies[user] = cookie
	else:
		while len(cookie.tokens) >= 16:
			cookie.tokens.pop(0)

	cookie.tokens.append(token)

	resp.set_cookie("auth", token)

	return resp


if __name__ == '__main__':
	app.connect('localhost', 'root', '')
	app.run(debug=True)
