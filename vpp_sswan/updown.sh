#!/bin/bash

set charon.plugins.kernel-vpp.use_tunnel_mode_sa = no

set -o nounset
set -o errexit

#set -x

#IF="ipip${PLUTO_UNIQUEID}"
IF="ipsec${PLUTO_UNIQUEID}"

case "${PLUTO_VERB}" in
    up-client)
	echo "up-client"
	echo "PLUTO_ME=${PLUTO_ME}"
	echo "PLUTO_PEER=${PLUTO_PEER}"
	echo "PLUTO_PEER_CLIENT=${PLUTO_PEER_CLIENT}"
	echo "PLUTO_REQID=${PLUTO_REQID}"
	echo "PLUTO_UNIQUEID=${PLUTO_UNIQUEID}"

##	vppctl "create ipip tunnel src ${PLUTO_ME} dst ${PLUTO_PEER} instance ${PLUTO_REQID} p2p"
#	vppctl "ipsec itf create instance ${PLUTO_REQID}"
#	vppctl "ipsec tunnel protect $IF sa-in 1 sa-out 2"
#	vppctl "set interface unnumbered $_IF use loop100"
	vppctl "set interface state $IF up"
	vppctl "ip route add ${PLUTO_PEER_CLIENT} via $IF"
        ;;
    down-client)

	echo "down-client $IF"
	echo "PLUTO_REQID=${PLUTO_REQID}"
	echo "PLUTO_UNIQUEID=${PLUTO_UNIQUEID}"

	vppctl "ip route del ${PLUTO_PEER_CLIENT} via $IF"
        vppctl "ipsec itf delete $IF"
#	sw_if_index=`vppctl "show interface $IF" | tail -1 | awk '{print $2}'`
#	vppctl "delete ipip tunnel sw_if_index $sw_if_index"
        ;;
esac
