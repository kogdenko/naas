COMPILER='clang'

def flags_to_string(flags):
	return ' ' + ' '.join(flags)

def vpp_lcpd(env, deps):
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
		'-lnaas-common',
		'-lnaas-vpp',
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
	prog = env.Program("bin/vpp-lcpd", "vpp-lcpd/main.c")
	for dep in deps:
		Requires(prog, dep)


def naas_common(env):
	srcs = [
		'naas-common/utils.c',
		'naas-common/strbuf.c',
		'naas-common/log.c',
		'naas-common/list.c',
	]
	env = env.Clone()
	return env.SharedLibrary('bin/libnaas-common.so', srcs)


def naas_vpp(env, deps):
	srcs = [
		'naas-vpp/api.c',
	]

	ldflags = [
		'-lvppinfra',
		'-lvlibmemoryclient',
		'-lvppapiclient',
		'-lvlibapi',
	]

	env = env.Clone()
	env.Append(LINKFLAGS = flags_to_string(ldflags))
	lib = env.SharedLibrary('bin/libnaas-vpp.so', srcs)
	for dep in deps:
		Requires(lib, dep)


def route_based_updown(env, deps):
	sswan = "root/vpp/build-root/build-vpp-native/external/sswan"

	cflags = [
		'-I/' + sswan + '/src/libcharon/plugins/vici/',
	]

	ldflags = [
		'-L/usr/lib/ipsec',
		'-lstrongswan',
		'-lvici',
		'-lnaas-common',
	]

	srcs = [
		'route-based-updown/main.c',
	]

	env = env.Clone()
	env.Append(CFLAGS = flags_to_string(cflags))
	env.Append(LINKFLAGS = flags_to_string(ldflags))
	prog = env.Program('bin/route-based-updown', srcs)
	for dep in deps:
		Requires(prog, dep)


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

libnaas_common = naas_common(env)
libnaas_vpp = naas_vpp(env, [ libnaas_common ])
vpp_lcpd(env, [ libnaas_common, libnaas_vpp ])
route_based_updown(env, [ libnaas_common, libnaas_vpp ])
