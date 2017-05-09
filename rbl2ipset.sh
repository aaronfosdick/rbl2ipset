#!/bin/bash
declare -a sources=(
"http://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt"
"https://reputation.alienvault.com/reputation.generic |grep Malicious |/usr/bin/awk '{print \$1}'"
"http://www.openbl.org/lists/base.txt"
"http://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt"
"http://www.talosintelligence.com/feeds/ip-filter.blf"
)
 
declare -a iplist
INDEX=0
for i in "${sources[@]}"
do
   readarray -t -O $INDEX iplist < <(eval curl -s $i)
   INDEX=${#iplist[@]}
done
 
# Generate list of unique IPs
printf '%s\n' "${iplist[@]}"  |grep -v "#"|grep  -v "<" |grep -v '^$'|sort|uniq >/tmp/ipblocklist
# whitelist my Public IP address in the event it makes the list
## sed -i 's/a.b.c.d//g' /tmp/ipblocklist
 
# Create ipset list
if [ `ipset list -n|grep -c blocklist` == 0 ]; then
         ipset create blocklist hash:ip maxelem 98304 timeout 604800
fi
 
# Create IPTables chain
if [ `iptables -L|grep -c IPBLOCKLIST` == 0 ]; then
        iptables -N IPBLOCKLIST
        iptables -A IPBLOCKLIST -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A IPBLOCKLIST -m set --match-set blocklist src -j DROP
fi
 
# Import addresses and set to expire in one week
while read IP; do ipset add -exist blocklist $IP; done < /tmp/ipblocklist
