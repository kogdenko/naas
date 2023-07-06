## API

Login:

	POST /api/v1.0/login
	{
		"user": string
		"password": string
	}

	200 OK


Get site list:

	GET /api/v1.0/config/list?user=STRING

	200 OK
	{
		"user": string
		"sites": string[]
	}


Get site info:

	GET /api/v1.0/config/get?user=STRING&config=STRING

	200 OK
	<SITE_CONFIG>


Add site:

	POST /api/v1.0/config/add
	<SITE_CONFIG>

	200 OK


Edit site:

	POST /api/v1.0/config/mod
	<SITE_CONFIG>

	200 OK


Delete site:

	POST /api/v1.0/config/del
	<SITE_CONFIG>

	200 OK


Template SITE_CONFIG:

	{
		"user":			string,
		"config":		string,
		"gateway":		string,
		"mobike":		boolean,
		"secret":		string,
		"local_ts":		string[],
		"remote_ts":	string[],
	}
