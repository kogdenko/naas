# vpp-lcpd - Helper daemon for managing VPP srv6 routes

Listen netlink and add/del routes to VPP, which is not handled by native lcp plugin. Based on libnl3

## Build
Build patched libnl (https://github.com/kogdenko/libnl) with --prefix=/opt/
scons
scons install
