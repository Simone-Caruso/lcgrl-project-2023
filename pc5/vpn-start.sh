#!/bin/bash
printf "%s" "waiting for VPN-Server ..."
while ! ping -c 1 -n -w 1 149.50.83.193 &> /dev/null
do
    printf "%c" "."
done
printf "\n%s\n"  "VPN-Server is reachable."

/etc/init.d/openvpn start
