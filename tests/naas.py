import sys
import subprocess

def bytes_to_str(b):
	return b.decode('utf-8').strip()


def print_log(s):
	print(s)

def system(cmd):
	proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	try:
		out, err = proc.communicate(timeout = 5)
	except Exception as exc:
		proc.kill()
		print_log("Command '%s' failed: '%s'" % (cmd, sys.exc_info()[0]))
		raise exc

	out = bytes_to_str(out)
	err = bytes_to_str(err)

	if proc.returncode != 0:
		raise RuntimeError("Command '%s' failed with code '%d':\n%s" %
				(cmd, proc.returncode, err))

	return out, err
