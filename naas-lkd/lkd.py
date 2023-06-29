#!/usr/bin/python
import os
import sys
import ipaddress
import threading
import mysql.connector

sys.path.append(os.path.expanduser(os.path.dirname(os.path.realpath(__file__))) + "/..")
from naaspy import swanctl

from flask import Flask, jsonify, abort, request

class TrafficSelector:
	def __init__(self, net=None):
		self.id = None
		if net != None:
			self.start_addr = net.network_address
			self.end_addr = net.network_address + (net.num_addresses - 1)


	def __eq__(self, other):
		return (self.start_addr == other.start_addr and self.end_addr == other.end_addr)


class Backend(Flask, swanctl.MySql):
	def __init__(self):
		Flask.__init__(self, __name__)
		swanctl.MySql.__init__(self)
		self.lock = threading.Lock()


	def create_traffic_selectors(self, arg):
		traffic_selectors = []
		for net in arg:
			traffic_selectors.append(TrafficSelector(ipaddress.ip_network(net)))
		return traffic_selectors


	def get_traffic_selectors(self, child_id, kind):
		cursor = self.execute(("select traffic_selector from child_config_traffic_selector "
				"where child_cfg = %d and kind = %d" % (child_id, kind)))

		traffic_selectors = []
		while True:
			row = cursor.fetchone()
			if row == None:
				break
			ts = TrafficSelector()
			ts.id = int(row[0])

		for ts in traffic_selectors:
			cursor = self.execute(("select start_addr, end_addr from traffic_selectors "
					"where id = %d" % (ts.id)))
			row = cursor.fetchone()
			ts.start_addr = ipaddress.ip_address(int(row[0]))
			ts.end_addr = ipaddress.ip_address(int(row[1]))

		print(traffic_selectors)
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

		self.add_traffic_selectors(child_id, kind, traffic_selectors)
		self.del_traffic_selectors(child_id, old_traffic_selectors)
		

	def get_child_config_name(self, child_id):
		cursor = self.execute("select name from child_configs where id = %d" % child_id)
		row = cursor.fetchone()
		return row[0]


	def config_add_config(self, config, peer_id, local_ts, remote_ts):
		child_id = self.add_child_config(config, "naas-updown.sh")
		self.add_peer_config_child_config(peer_id, child_id)

		self.add_traffic_selectors(child_id, swanctl.TS_LOCAL, local_ts)
		self.add_traffic_selectors(child_id, swanctl.TS_REMOTE, remote_ts)

		return "ok"


	def config_add_ike(self, user, config, local_id, remote_id,
			mobike, secret, local_ts, remote_ts):
		ip_zero = ipaddress.ip_address("0.0.0.0")
		ike_id = self.add_ike_config(ip_zero, ip_zero)
		peer_id = self.add_peer_config(user, ike_id, local_id, remote_id)

		return self.config_add_config(config, peer_id, local_ts, remote_ts)


	def config_mod(self, user, config, mobike, secret, local_ts, remote_ts):
		local_id = self.add_identity(swanctl.ID_ANY, None)
		remote_id = self.add_identity(swanctl.ID_KEY_ID, 13) # TODO: Get VRF from db
		secret_id = self.add_shared_secret(secret)

		self.add_shared_secret_identity(secret_id, local_id)
		self.add_shared_secret_identity(secret_id, remote_id)

		cursor = self.execute(("select id, ike_cfg, local_id, remote_id, mobike "
				"from peer_configs where name = '%s'" %
				user))
		row = cursor.fetchone()
		if row == None:
			return self.config_add_ike(user, config,
					local_id, remote_id, secret_id,
					mobike, local_ts, remote_ts)

		peer_id = int(row[0])
		ike_id = int(row[1])
		old_local_id = int(row[2])
		old_remote_id = int(row[3])
		old_mobike = int(row[4])

		if local_id != old_local_id or remote_id != old_remote_id or mobike != old_mobike:
			self.execute(("update peer_configs set local_id=%d, remote_id=%d, mobike=%d "
				"where id = %d" % (local_id, remote_id, mobike, peer_id)))
			self.commit()

		cursor = self.execute(("select child_cfg from peer_config_child_config "
				"where peer_cfg = %d" % peer_id) )
		while True:
			row = cursor.fetchone()
			if row == None:
				self.config_add_config(config, peer_id, local_ts, remote_ts)
				break
			child_id = int(row[0])
			child_name = self.get_child_config_name(child_id)
			if child_name == config:
				self.config_mod_traffic_selectors(child_id,
						swanctl.TS_LOCAL, local_ts)
				self.config_mod_traffic_selectors(child_id,
						swanctl.TS_REMOTE, remote_ts)
				break

		
		return "ok"


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

	user = request.json['user']
	config = request.json['config']
	secret = request.json['secret']
	local_ts = app.create_traffic_selectors(request.json['local_ts'])
	if not len(local_ts):
		abort(400)
	remote_ts = app.create_traffic_selectors(request.json['remote_ts'])
	if not len(remote_ts):
		abort(400)

	with app.lock:
		message = app.config_mod(user, config, mobike, secret, local_ts, remote_ts)

	return jsonify({'message': message}), 200


if __name__ == '__main__':
	app.run(debug=True)

