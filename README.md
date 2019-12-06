# ConeNATd
User-space-only program implements Full Cone NAT support.

It performs DNAT dynamically based on conntrack NEW/DESTROY events.

## How It Works
```
LAN Host            Netfilter SNAT         WAN Host
10.0.0.10:1024  ->  123.45.67.89:1234  ->  1.1.1.1:1111
                    |
                    | Conntrack Event [NEW]
                    V
LAN Host            ConeNATd DNAT          WAN Host
10.0.0.10:1024  <-  123.45.67.89:1234  <-  2.2.2.2:2222
10.0.0.10:1024  <-  123.45.67.89:1234  <-  3.3.3.3:3333
...
10.0.0.10:1024  <-  123.45.67.89:1234  <-  N.N.N.N:NNNN
```
```
LAN Host            Netfilter SNAT         WAN Host
10.0.0.10:1024  ->  123.45.67.89:1234  ->  1.1.1.1:1111
                    |
                    | Conntrack Event [DESTROY]
                    V
LAN Host            ConeNATd DNAT          WAN Host
10.0.0.10:1024  !X  123.45.67.89:1234  <-  2.2.2.2:2222
10.0.0.10:1024  !X  123.45.67.89:1234  <-  3.3.3.3:3333
...
10.0.0.10:1024  !X  123.45.67.89:1234  <-  N.N.N.N:NNNN
```

## Dependencies
- libmnl
- libpthread
- libnetfilter_queue
- libnetfilter_conntrack

## Compile
```
# make
```

## Usage
Using with iptables and NFQUEUE, see example.

```
conenatd -n <nat-ip> -q <queue-num> -m <fwmark> [-p <pid-file>] [-f foreground]
```

Since the NAT type implemented by netfilter is symmetrical, a single SNAT source port may be related to multiple tuples, which will cause conflicts. The workaround is to configure the SNAT source port range for each LAN host, just like CGN/LSN does.

**Example**

Port range are divided into two parts: 1024-10239 and 10240-65535.

The first part is used for normal NAT, the second part is used for ConeNATd.

Each host (10.0.0.101-10.0.0.109) have 6144 ports for Full Cone NAT.

```
# iptables -t nat -N CONENATD_PRE
# iptables -t nat -A CONENATD_PRE -p udp -m mark --mark 2000 -j RETURN # Skip packtes marked by ConeNATd
# iptables -t nat -A CONENATD_PRE -p udp --dport 0:1023 -j RETURN      # Skip reserved ports
# iptables -t nat -A CONENATD_PRE -p udp --dport 1024:10239 -j RETURN  # Skip ports of the first part
# iptables -t nat -A CONENATD_PRE -p udp -j NFQUEUE --queue-num 1000   # ConeNATd DNAT
# iptables -t nat -I PREROUTING -i eth0 -j CONENATD_PRE

# iptables -t nat -N CONENATD_POST
# iptables -t nat -A CONENATD_POST -p udp -s 10.0.0.101 -j MASQUERADE --to-ports 10240-16383
# iptables -t nat -A CONENATD_POST -p udp -s 10.0.0.102 -j MASQUERADE --to-ports 16384-22527
# iptables -t nat -A CONENATD_POST -p udp -s 10.0.0.103 -j MASQUERADE --to-ports 22528-28671
# iptables -t nat -A CONENATD_POST -p udp -s 10.0.0.104 -j MASQUERADE --to-ports 28672-34815
# iptables -t nat -A CONENATD_POST -p udp -s 10.0.0.105 -j MASQUERADE --to-ports 34816-40959
# iptables -t nat -A CONENATD_POST -p udp -s 10.0.0.106 -j MASQUERADE --to-ports 40960-47103
# iptables -t nat -A CONENATD_POST -p udp -s 10.0.0.107 -j MASQUERADE --to-ports 47104-53247
# iptables -t nat -A CONENATD_POST -p udp -s 10.0.0.108 -j MASQUERADE --to-ports 53248-59391
# iptables -t nat -A CONENATD_POST -p udp -s 10.0.0.109 -j MASQUERADE --to-ports 59392-65535
# iptables -t nat -A CONENATD_POST -p udp -j MASQUERADE --to-ports 1024-10239
# iptables -t nat -I POSTROUTING -o eth0 -j CONENATD_POST

# conenatd -n 123.45.67.89 -q 1000 -m 2000
```
