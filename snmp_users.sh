#!/bin/bash
# Creates the SNMPv3 users of the end-to-end tests (testdata/snmp_users.txt) in snmpd's configuration, each with
# read-only access at its security level.
set -euo pipefail

users="$(dirname "$0")/testdata/snmp_users.txt"
conf="${SNMPD_CONF:-/etc/snmp/snmpd.conf}"

while read -r user auth authpass priv privpass; do
  case "$user" in "" | "#"*) continue ;; esac
  if [ "$auth" = NoAuth ]; then
    echo "createUser $user"
    echo "rouser $user noauth"
  elif [ "$priv" = NoPriv ]; then
    echo "createUser $user $auth $authpass"
    echo "rouser $user auth"
  else
    echo "createUser $user $auth $authpass $priv $privpass"
    echo "rouser $user priv"
  fi
done <"$users" >>"$conf"

# enable ipv6 TODO restart fails - need to enable ipv6 on interface; spin up a Linux instance to check this
# sed -i -e '/agentAddress/ s/^/#/' -e '/agentAddress/ s/^##//' /etc/snmp/snmpd.conf
