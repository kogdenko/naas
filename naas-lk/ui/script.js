function j_id(id) {
	return document.getElementById(id);
}

function j_format(fmt) {
	let i = 1;
	const args = arguments;
	return fmt.replace(/%s/g, function(match) {
		return args[i++];
	});
}

function j_request(method, url, obj, onload) {
	const h = new XMLHttpRequest();
	h.open(method, url);
	h.onload = onload;
	h.setRequestHeader("Content-Type", "application/json")
	h.send(JSON.stringify(obj));
}
