#!/bin/bash

# set charon.install_virtual_ip = no to prevent the daemon from also installing the VIP

set charon.plugins.kernel-vpp.use_tunnel_mode_sa = no

set -o nounset
set -o errexit

#set -x

VTI_IF="vti${PLUTO_REQID}"
IPIP_IF="ipip${PLUTO_REQID}"


case "${PLUTO_VERB}" in
    up-client)
	echo "up-client"
	echo "PLUTO_ME=${PLUTO_ME}"
	echo "PLUTO_PEER=${PLUTO_PEER}"
	echo "PLUTO_PEER_CLIENT=${PLUTO_PEER_CLIENT}"
	echo "PLUTO_REQID=${PLUTO_REQID}"
	echo "PLUTO_UNIQUEID=${PLUTO_UNIQUEID}"

	naas-route-based-updown -C 6000 --reqid ${PLUTO_REQID} --uniqueid ${PLUTO_UNIQUEID} --me ${PLUTO_ME} --peer ${PLUTO_PEER} --peer-client ${PLUTO_PEER_CLIENT}


#	vppctl "create ipip tunnel src ${PLUTO_ME} dst ${PLUTO_PEER} instance ${PLUTO_REQID} p2p"
#	vppctl "ipsec tunnel protect $IPIP_IF sa-in 1 sa-out 2"
#	vppctl "set interface unnumbered $IPIP_IF use loop100"
#	vppctl "set interface state $IPIP_IF up"
#	vppctl "ip route add ${PLUTO_PEER_CLIENT} via $IPIP_IF"
        ;;
    down-client)
	sw_if_index=`vppctl "show interface $IPIP_IF" | tail -1 | awk '{print $2}'`

	echo "down-client $sw_if_index"
	echo "PLUTO_REQID=${PLUTO_REQID}"
	echo "PLUTO_UNIQUEID=${PLUTO_UNIQUEID}"

	vppctl "delete ipip tunnel sw_if_index $sw_if_index"
        ;;
esac
