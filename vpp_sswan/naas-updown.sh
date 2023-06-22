#!/bin/bash

set -o nounset
set -o errexit

#set -x

IF="ipsec${PLUTO_UNIQUEID}"
NATS_SERVER="bus.naas.svc.cluster.local"

case "${PLUTO_VERB}" in
    up-client)
	echo "up-client"
	echo "PLUTO_ME=${PLUTO_ME}"
	echo "PLUTO_PEER=${PLUTO_PEER}"
	echo "PLUTO_PEER_ID=${PLUTO_PEER_ID}"
	echo "PLUTO_PEER_CLIENT=${PLUTO_PEER_CLIENT}"
	echo "PLUTO_REQID=${PLUTO_REQID}"
	echo "PLUTO_UNIQUEID=${PLUTO_UNIQUEID}"

	nats --server $NATS_SERVER pub updown "add ${PLUTO_UNIQUEID} ${PLUTO_PEER_CLIENT} ${PLUTO_PEER_ID} 1"
	
	vppctl "set interface state $IF up"
	vppctl "ip route add ${PLUTO_PEER_CLIENT} via $IF"
        ;;
    down-client)
	echo "down-client"
	echo "PLUTO_REQID=${PLUTO_REQID}"
	echo "PLUTO_UNIQUEID=${PLUTO_UNIQUEID}"

	vppctl "ip route del ${PLUTO_PEER_CLIENT} via $IF"
        vppctl "ipsec itf delete $IF"

	nats --server $NATS_SERVER pub updown "del ${PLUTO_UNIQUEID} ${PLUTO_PEER_CLIENT} ${PLUTO_PEER_ID} 1"
        ;;
esac
