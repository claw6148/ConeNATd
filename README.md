# ConeNATd
基于NFQUEUE的用户模式Full-cone NAT实现。

## 用法

```
conenatd
  -n <NAT源地址>
  -s <SNAT队列号>
  -d <DNAT队列号>
  -m <包标记>
  [-i <端口范围起始> 默认1024]
  [-x <端口范围结束> 默认65535]
  [-t <UDP新建超时（无回包）> 默认60秒]
  [-o <UDP建立超时（有回包）> 默认300秒]
  [-e <每个内部地址的最大端口数> 默认0=无限制]
  [-p <PID文件>]
  [-f 前台运行]
```

## 配置示例

### 基本配置

```
#!/bin/sh

NAT_IP=外部接口地址
EXT_IF=外部接口
INT_IF=内部接口

SNAT_QN=1001
DNAT_QN=1002
FW_MARK=2000

iptables -t mangle -I PREROUTING -i ${EXT_IF} -p udp -m mark ! --mark ${FW_MARK} -j NFQUEUE --queue-num ${DNAT_QN}
iptables -t mangle -I FORWARD -i ${INT_IF} -o ${EXT_IF} -p udp -m mark ! --mark ${FW_MARK} -j NFQUEUE --queue-num ${SNAT_QN}
iptables -t nat -I POSTROUTING -o ${EXT_IF} -p udp -m mark --mark ${FW_MARK} -j ACCEPT

conenatd -n ${NAT_IP} -s ${SNAT_QN} -d ${DNAT_QN} -m ${FW_MARK}
```

### 进阶配置1 限制每个内部地址的最大端口数

为防止外部端口被单个内部地址耗尽，可在`conenatd`追加参数`-e ?`以限制每个内部地址的最大端口数。

以端口范围[1024, 65535]，每个内部地址可**同时**使用1024个端口为例：

单个外部地址可为(65535-1024+1)/1024=63个内部地址提供Full-cone NAT服务。

### 进阶配置2 与原生NAT共存

对于DNS查询（目的端口53）之类不需要使用Full-cone NAT的业务可交由原生NAT处理，以节省Full-cone NAT端口资源。

划分端口范围：

- 目的端口在[1, 1023]范围内的连接交由原生NAT处理，并限制NAT源端口在[1024, 10239]范围内
- 目的端口在[1024, 65535]范围内的连接交由ConeNATd处理，并限制NAT源端口在[10240, 65535]范围内

配置如下：

```
#!/bin/sh

NAT_IP=外部接口地址
EXT_IF=外部接口
INT_IF=内部接口

SNAT_QN=1001
DNAT_QN=1002
FW_MARK=2000

iptables -t mangle -I PREROUTING -i ${EXT_IF} -p udp ! --sport 1:1024 -m mark ! --mark ${FW_MARK} -j NFQUEUE --queue-num ${DNAT_QN}
iptables -t mangle -I FORWARD -i ${INT_IF} -o ${EXT_IF} -p udp ! --dport 1:1024 -m mark ! --mark ${FW_MARK} -j NFQUEUE --queue-num ${SNAT_QN}
iptables -t nat -I POSTROUTING -o ${EXT_IF} -p udp -j SNAT --to ${NAT_IP}:1024-10239
iptables -t nat -I POSTROUTING -o ${EXT_IF} -p udp -m mark --mark ${FW_MARK} -j ACCEPT

conenatd -n ${NAT_IP} -s ${SNAT_QN} -d ${DNAT_QN} -m ${FW_MARK} -i 10240 -x 65535
```

## 已知问题

### 丢包

大带宽时存在丢包现象，原因是默认的netlink socket缓冲区不足。

适当增大`net.core.rmem_default`和`net.core.rmem_max`能缓解丢包现象：

```
# sysctl -w net.core.rmem_default=?
# sysctl -w net.core.rmem_max=?
```

## 文件描述符数量

为避免与本机使用UDP的程序发生端口冲突，ConeNATd会为每个NAT会话绑定对应端口占坑。可能需要用`ulimit`调整最大fd数。
