import os
import shutil
import platform
import subprocess

COMPILER='clang'

def die(s):
    print(s)
    Exit(1)


def bytes_to_str(b):
    return b.decode('utf-8').strip()


def system(cmd, failure_tollerance=False):
    proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = proc.communicate()
    except:
        proc.kill();
        die("Command '%s' failed, exception: '%s'" % (cmd, sys.exc_info()[0]))

    out = bytes_to_str(out)
    err = bytes_to_str(err)
    rc = proc.returncode

#    print("$ %s # $? = %d\n%s\n%s" % (cmd, rc, out, err))

    if rc != 0 and not failure_tollerance:
        die("Command '%s' failed, return code: %d" % (cmd, rc))

    return rc, out, err


def get_git_version():
    if True:
        cmd = "git describe --tags --always"
        rc, out, _ = system(cmd)
        if rc != 0:
            die("Cannot extract gbtcp version")
        return out.strip()
    else:
        cmd = "git log -1 --format=%H"
        commit = system(cmd)[1].strip()
        if len(commit) != 40:
            die("Cannot extract gbtcp version")
        return commit


def flags_to_string(flags):
	return ' ' + ' '.join(flags)


def install(env, item, path):
    env.Install(path, item)
    env.Alias('install', path)


def install_lib(env, lib):
	lib_path = '/usr/local/lib'
	install(env, lib, lib_path)


def install_prog(env, prog):
	install(env, prog, '/usr/local/bin')


def naas_vpp_lcpd(env, deps):
	seg6_local_vrftable_test_c = """
#include <stdio.h>
#include <linux/seg6_local.h>

int
main()
{
        printf("%d", SEG6_LOCAL_VRFTABLE);
        return 0;
}
"""

	global libnaas_ld

	ldflags = [
		'-L/opt/libnl-227.27.0/lib',
		'-l:libnl-3.so.200.27.0',
		'-l:libnl-route-3.so.200.27.0',
		'-l:libnl-cli-3.so.200.27.0',
		libnaas_ld,
	]

	cflags = [
		'-I/opt/libnl-227.27.0/include/libnl3/',
	]

	env = env.Clone()

	conf = Configure(env)

	result = conf.TryLink(seg6_local_vrftable_test_c, '.c')
	if result:
		cflags.append('-DHAVE_SEG6_LOCAL_VRFTABLE')
	print("Checking for SEG6_LOCAL_VRFTABLE... ", "yes" if result else "no")
	env = conf.Finish()

	env.Append(CFLAGS = flags_to_string(cflags))
	env.Append(LINKFLAGS = flags_to_string(ldflags))
	prog = env.Program("bin/naas-vpp-lcpd", "naas-vpp-lcpd/main.c")
	for dep in deps:
		Requires(prog, dep)
	install_prog(env, prog)
	return prog


def build_libnaas(env):
	global libnaas_name

	srcs = [
		'libnaas/utils.c',
		'libnaas/strbuf.c',
		'libnaas/log.c',
		'libnaas/list.c',
		'libnaas/api.c',
	]

	ldflags = [
		'-lvppinfra',
		'-lvlibmemoryclient',
		'-lvppapiclient',
		'-lvlibapi',
	]

	env = env.Clone()
	env.Append(LINKFLAGS = flags_to_string(ldflags))

	lib = env.SharedLibrary('bin/' + libnaas_name, srcs)
	install_lib(env, lib)
	return lib


def get_sswan():
	sswan = GetOption('sswan')
	if sswan == None:
#		sswan = "/root/vpp-latest/build-root/build-vpp-native/external/sswan"
		die("Option '--sswan' not specified")
	return sswan


def vpp_sswan(env, deps):
	global libnaas_ld
	sswan = get_sswan()

	cflags = [
		'-include ' + sswan + '/config.h',
		'-I' + sswan + '/src/libstrongswan',
		'-I' + sswan + '/src/libcharon',
	]

	srcs = [
		'vpp_sswan/kernel_vpp_plugin.c',
	]

	ldflags = [
		'-lvppinfra',
#		'-lvlibmemoryclient',
		'-lvlibapi',
		'-lsvm',
		'-lvppapiclient',
		libnaas_ld,
	]

	env = env.Clone()
	env.Append(CFLAGS = flags_to_string(cflags))
	env.Append(LINKFLAGS = flags_to_string(ldflags))
	lib = env.SharedLibrary('bin/libstrongswan-kernel-vpp.so', srcs)
	for dep in deps:
		Requires(lib, dep)
	return lib


def build_deb(env):
	global git_version

	DEBNAME = "naas"
	DEBVERSION = git_version
	DEBMAINT = "Konstantin Kogdenko <k.kogdenko@gmail.com>"
	DEBARCH = "amd64"
	DEBDEPENDS = "vpp, vpp-dev, libvppinfra, libvppinfra-dev, libstrongswan, strongswan-swanctl"
	DEBDESC = "MTS Naas Package"

	libnl_path = "opt/libnl-227.27.0/lib/"

	libnl = libnl_path + "libnl-3.so.200.27.0"
	libnl_symlink = libnl_path + "libnl-3.so.200"

	libnl_route = libnl_path + "libnl-route-3.so.200.27.0"
	libnl_route_symlink = libnl_path + "libnl-route-3.so.200"

	libnl_cli = libnl_path + "libnl-cli-3.so.200.27.0"
	libnl_cli_symlink = libnl_path + "libnl-cli-3.so.200"

	libnl_nf = libnl_path + "libnl-nf-3.so.200.27.0"
	libnl_nf_symlink = libnl_path + "libnl-nf-3.so.200"

	vpp_lcpd = "naas-vpp-lcpd"

	DEBFILES = [
		("etc/ld.so.conf.d/ipsec.conf", "#libnaas/ld-ipsec.conf"),
		("usr/local/lib/" + libnaas_name, "#bin/" + libnaas_name),
		(libnl, "/" + libnl),
		(libnl_symlink, "/" + libnl_symlink),
		(libnl_route, "/" + libnl_route),
		(libnl_route_symlink, "/" + libnl_route_symlink),
		(libnl_cli, "/" + libnl_cli),
		(libnl_cli_symlink, "/" + libnl_cli_symlink),
		(libnl_nf, "/" + libnl_nf),
		(libnl_nf_symlink, "/" + libnl_nf_symlink),
		("usr/local/bin/" + vpp_lcpd, "#bin/" + vpp_lcpd),
		("etc/naas/kernel-vpp.conf", "#vpp_sswan/kernel-vpp.conf"),
		("etc/naas/libstrongswan-kernel-vpp.so", "#bin/libstrongswan-kernel-vpp.so"),
		("lib/systemd/system/naas-keeper.service", "vpp_sswan/naas-keeper.service"),
		("usr/local/bin/naas-keeper.sh", "vpp_sswan/naas-keeper.sh"),
	]

	debpkg = '#%s_%s_%s.deb' % (DEBNAME, git_version, DEBARCH)

	env.Alias("deb", debpkg)

	DEBCONTROLFILE = os.path.join(DEBNAME, "DEBIAN/control")

	try:
		shutil.rmtree(DEBNAME)
	except:
		pass

	for f in DEBFILES:
		dest = os.path.join(DEBNAME, f[0])
		env.Depends(debpkg, dest)
		env.Command(dest, f[1], Copy('$TARGET','$SOURCE'))
		env.Depends(DEBCONTROLFILE, dest)

	CONTROL_TEMPLATE = """
Package: %s
Priority: extra
Section: misc
Installed-Size: %s
Maintainer: %s
Architecture: %s
Version: %s
Depends: %s
Description: %s

"""

	env.Depends(debpkg, DEBCONTROLFILE)
	env.Depends(DEBCONTROLFILE, env.Value(git_version))

	def make_control(target=None, source=None, env=None):
		installed_size = 0
		for i in DEBFILES:
			installed_size += os.stat(str(env.File(i[1])))[6]
		control_info = CONTROL_TEMPLATE % (
			DEBNAME, installed_size, DEBMAINT, DEBARCH,
			git_version, DEBDEPENDS, DEBDESC)
		f = open(str(target[0]), 'w')
		f.write(control_info)
		f.close()

	env.Command(DEBCONTROLFILE, None, make_control)

	env.Command(debpkg, DEBCONTROLFILE,
        	    "fakeroot dpkg-deb -b %s %s" % ("%s" % DEBNAME, "$TARGET"))


ldflags = [
	'-L./bin',
]

cflags = [
	'-g',
	'-O0',
	'-Wall',
	'-std=gnu99',
	'-I.',
]

env = Environment(CC = COMPILER)
env.Append(CFLAGS = flags_to_string(cflags))
env.Append(LINKFLAGS = flags_to_string(ldflags))

git_version = get_git_version()
libnaas_name = 'libnaas.so.' + git_version
libnaas_ld = '-l:' + libnaas_name

env['LINKCOM'] = '$LINK -o $TARGET $SOURCES $LINKFLAGS $__RPATH $_LIBDIRFLAGS $_LIBFLAGS'

AddOption('--sswan', type='string', action='store', help='Strongswan sources')

libnaas = build_libnaas(env)
libstrongswan_kernel_vpp = vpp_sswan(env, [ libnaas ])

naas_vpp_lcpd(env, [ libnaas ])

if 'deb' in COMMAND_LINE_TARGETS:
	build_deb(env)
