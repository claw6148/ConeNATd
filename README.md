# ConeNATd
基于NFQUEUE的用户模式Full Cone NAT实现，仅支持UDP。

## 用法

```
conenatd
  -n <NAT源地址>
  -s <SNAT 队列号>
  -d <DNAT 队列号>
  -m <包标记>
  [-i <端口范围起始> 默认1024]
  [-x <端口范围结束> 默认65535]
  [-t <UDP新建超时（无回包）> 默认60秒]
  [-o <UDP建立超时（有回包）> 默认300秒]
  [-p <PID文件>]
  [-f 前台运行]
```

## 配置示例

```
#!/bin/sh

NAT_IP=外部接口IP
EXT_IF=外部接口
INT_IF=内部接口

SNAT_QN=1001
DNAT_QN=1002
FW_MARK=2000

iptables -t mangle -I PREROUTING -p udp -i ${EXT_IF} -m mark ! --mark ${FW_MARK} -j NFQUEUE --queue-num ${DNAT_QN}
iptables -t mangle -I FORWARD -p udp -i ${INT_IF} -o ${EXT_IF} -m mark ! --mark ${FW_MARK} -j NFQUEUE --queue-num ${SNAT_QN}
iptables -t nat -I POSTROUTING -o ${EXT_IF} -p udp -j ACCEPT

conenatd -n ${NAT_IP} -s ${SNAT_QN} -d ${DNAT_QN} -m ${FW_MARK} -i 10240 -x 65535
```

## 性能问题

大带宽时存在丢包现象，原因是默认的netlink socket缓冲区不足。

适当增大`net.core.rmem_default`和`net.core.rmem_max`能缓解丢包现象：

```
# sysctl -w net.core.rmem_default=?
# sysctl -w net.core.rmem_max=?
```
