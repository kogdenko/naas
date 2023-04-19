import platform

COMPILER='clang'

def die(s):
    print(s)
    Exit(1)


def flags_to_string(flags):
	return ' ' + ' '.join(flags)


def install(env, item, path):
    env.Install(path, item)
    env.Alias('install', path)


def install_lib(env, lib):
#	if platform.architecture()[0] == "64bit":
#		lib_path = '/usr/lib64'
#	else:
#		lib_path = '/usr/lib'
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

	ldflags = [
		'-L/opt/libnl-227.27.0/lib',
		'-l:libnl-3.so.200.27.0',
		'-l:libnl-route-3.so.200.27.0',
		'-l:libnl-cli-3.so.200.27.0',
		'-lnaas',
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

	lib = env.SharedLibrary('bin/libnaas.so', srcs)
	install_lib(env, lib)
	return lib


def get_sswan():
	sswan = GetOption('sswan')
	if sswan == None:
#		sswan = "/root/vpp-latest/build-root/build-vpp-native/external/sswan"
		die("Option '--sswan' not specified")
	return sswan


def vpp_sswan(env, deps):
	sswan = get_sswan()

	cflags = [
		'-include ' + sswan + '/config.h',
		'-I' + sswan + '/src/libstrongswan',
		'-I' + sswan + '/src/libcharon',
	]

	srcs = [
		'vpp_sswan/kernel_vpp_plugin.c',
		'vpp_sswan/kernel_vpp_shared.c',
		'vpp_sswan/kernel_vpp_ipsec.c',
		'vpp_sswan/kernel_vpp_net.c',
	]

	ldflags = [
		'-lvppinfra',
		'-lvlibmemoryclient',
		'-lvlibapi',
		'-lsvm',
		'-lvppapiclient',
		'-lnaas',
	]

	env = env.Clone()
	env.Append(CFLAGS = flags_to_string(cflags))
	env.Append(LINKFLAGS = flags_to_string(ldflags))
	lib = env.SharedLibrary('bin/libstrongswan-kernel-vpp.so', srcs)
	for dep in deps:
		Requires(lib, dep)
	return lib


def naas_route_based_updown(env, deps):
	sswan = get_sswan() 

	cflags = [
		'-I/' + sswan + '/src/libcharon/plugins/vici/',
	]

	ldflags = [
		'-L/usr/lib/ipsec',
		'-lstrongswan',
		'-lvici',
		'-lnaas',
	]

	srcs = [
		'naas-route-based-updown/main.c',
	]

	env = env.Clone()
	env.Append(CFLAGS = flags_to_string(cflags))
	env.Append(LINKFLAGS = flags_to_string(ldflags))
	prog = env.Program('bin/naas-route-based-updown', srcs)
	for dep in deps:
		Requires(prog, dep)
	install_prog(env, prog)
	return prog


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

env['LINKCOM'] = '$LINK -o $TARGET $SOURCES $LINKFLAGS $__RPATH $_LIBDIRFLAGS $_LIBFLAGS'

AddOption('--sswan', type='string', action='store', help='Strongswan sources')

libnaas = build_libnaas(env)
libstrongswan_kernel_vpp = vpp_sswan(env, [ libnaas ])
naas_vpp_lcpd(env, [ libnaas, libstrongswan_kernel_vpp ])
naas_route_based_updown(env, [ libnaas ])
