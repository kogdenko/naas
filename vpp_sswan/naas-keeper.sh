#!/bin/bash

EXT_ADDR="77.105.183.51/29"
EXT_GW="77.105.183.49"

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
NC='\033[0m' # No Color

case $1 in
  up)
     if ( ! systemctl is-active -q vpp ); then
         echo -e "${RED}VPP isn't running while should. Aborted!${NC}"
         logger -t naas-keeper "Unable to start Strongswan, cause VPP service is in inactive state."
         exit 1
     elif [ -d /sys/class/net/eth0 ]; then
         ip link set dev eth0 up
         ip address add ${EXT_ADDR} dev eth0
         ip route add 10.0.0.0/8 via ${EXT_GW}
         sleep 4
         echo -e "Tap interface ${GRN}OK${NC}"
         exit 0
     else
         echo -e "${RED}Unknown conditions!${NC}"
         logger -t naas-keeper "Unable to start Strongswam due to unknown conditions. Please, check VPP LC-plugins. Seems like Eth0 is not present or unconfigurable"
         exit 1
     fi
  ;;
  down)
     if [ -d /sys/class/net/eth0 ]; then
         ip address del ${EXT_ADDR} dev eth0
         ip route del 10.0.0.0/8 via ${EXT_GW}
         sleep 2
         exit 0
     fi
  ;;
  start)
         systemctl stop vpp
         sleep 2
         systemctl stop strongswan
         sleep 2
#         killall -9 naas-route-based-updown &>/dev/null

     if ( ! systemctl is-active -q vpp && ! systemctl is-active -q strongswan); then
         systemctl start vpp
         sleep 4
         naas-keeper.sh up
         systemctl start strongswan
         sleep 2
         if ( systemctl is-active -q vpp ); then
            echo -e "Starting VPP ${GRN}OK${NC}"
         else
            echo -e "Starting VPP ${RED}FAILED${NC}"
            logger -t naas-keeper "Starting NaaS RAS Failed. Unable to start VPP. Aborted."
            exit 1
         fi
         if ( systemctl is-active -q strongswan ); then
            echo -e "Starting Strongswan ${GRN}OK${NC}"
         else
            echo -e "Starting Strongswan ${RED}FAILED${NC}"
            logger -t naas-keeper "Starting NaaS RAS failed. Unable to start Strongswan. Aborted."
            exit 1
         fi
         sleep infinity
     else
         echo -e "${RED}Unable to stop VPP, Strongswan or NaaS-Route_based-UpDown${NC}"
         logger -t naas-keeper "Unable to stop someone from VPP/Strongswan/Naas-route-based-updown. NaaS RAS expects all services to start in strict order. Aborted"
         exit 1
     fi
  ;;
  stop)
     systemctl stop vpp
     sleep 2
     systemctl stop strongswan
     sleep 2
#     killall -9 naas-route-based-updown &>/dev/null

     if ( ! systemctl is-active -q vpp && ! systemctl is-active -q strongswan); then
         echo -e "Stopping VPP ${GRN}OK${NC}"
         echo -e "Stopping Strongswan ${GRN}OK${NC}"
#         echo -e "Stopping Naas-Route-Based-UpDown ${GRN}OK${NC}"
         exit 0
     else
         if ( systemctl is-active -q vpp ); then
            echo -e "Stopping VPP ${RED}FAILED${NC}"
            logger -t naas-keeper "Stopping NaaS RAS. Unable to stop VPP. Passing"
         fi
         if ( systemctl is-active -q strongswan ); then
            echo -e "Stopping Strongswan ${RED}FAILED${NC}"
            logger -t naas-keeper "Stopping NaaS RAS. Unable to stop Strongswan. Passing"
         fi
         exit 1
     fi
  ;;
  restart)
     naas-keeper.sh stop && sleep 2 && naas-keeper.sh start
  ;;
  status)
# TBD...

  ;;

esac
