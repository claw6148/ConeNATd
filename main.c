//
//  conenatd.c
//  ConeNATd
//
//  Created by Chileung Law on 2019/12/6.
//  Copyright © 2019 Chileung Law. All rights reserved.
//
//  iptables -t mangle -I PREROUTING -p udp -i <ext-if> -m mark ! --mark <fw-mark> -j NFQUEUE --queue-num <dst-nat-queue-num>
//  iptables -t mangle -I FORWARD -p udp -i <int-if> -o <ext-if> -m mark ! --mark <fw-mark> -j NFQUEUE --queue-num <src-nat-queue-num>

#include <arpa/inet.h>
#include <fcntl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/udp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    uint32_t dst_ip;
    uint16_t dst_port;
    time_t active_time;
} fwd_item;

fwd_item fwd_table[0x10000];

uint32_t nat_ip;
uint32_t fw_mark;
uint16_t qn_src_nat, qn_dst_nat;
time_t nat_timeout = 60;

uint16_t checksum(uint32_t sum, uint16_t *buf, int size) {
    while (size > 1) {
        sum += *buf++;
        size -= sizeof(uint16_t);
    }
    if (size)
        sum += *(uint8_t *) buf;
    sum = (sum >> 16u) + (sum & 0xffffu);
    sum += (sum >> 16u);
    return (uint16_t) (~sum);
}

uint16_t checksum_tcpudp_ipv4(struct iphdr *iph) {
    uint32_t sum = 0;
    uint32_t iph_len = iph->ihl * 4;
    uint32_t len = ntohs(iph->tot_len) - iph_len;
    uint8_t *payload = (uint8_t *) iph + iph_len;
    sum += (iph->saddr >> 16u) & 0xFFFFu;
    sum += (iph->saddr) & 0xFFFFu;
    sum += (iph->daddr >> 16u) & 0xFFFFu;
    sum += (iph->daddr) & 0xFFFFu;
    sum += htons(iph->protocol);
    sum += htons(len);
    return checksum(sum, (uint16_t *) payload, len);
}

#define MIN_PORT    1024
#define MAX_PORT    65535

static int nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, const uint16_t *queue_num) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    int handled = 0;
    uint32_t id = 0;
    if (ph) id = ntohl(ph->packet_id);

    time_t now = time(NULL);
    void *pkt;
    int data_len = nfq_get_payload(nfa, (unsigned char **) &pkt);
    struct iphdr *ip = (struct iphdr *) pkt;
    struct udphdr *udp = (struct udphdr *) ((uint8_t *) ip + (ip->ihl << 2u));
    if (ip->protocol != IPPROTO_UDP) goto _out;

    if (*queue_num == qn_src_nat) {
        uint16_t src_port = 0;
        for (int i = 1; i < 0x10000; ++i) {
            fwd_item *item = &fwd_table[i];
            if (item->dst_ip != ip->saddr ||
                item->dst_port != udp->source ||
                item->active_time >= nat_timeout == 0 ||
                now - item->active_time >= nat_timeout)
                continue;
            item->active_time = now;
            src_port = i;
            break;
        }
        if (src_port == 0) {
            while (1) {
                src_port = MIN_PORT + (random() % (MAX_PORT - MIN_PORT + 1));
                fwd_item *item = &fwd_table[src_port];
                if (item->dst_ip != ip->daddr && now - item->active_time < nat_timeout) {
                    continue;
                }
                item->dst_port = udp->source;
                item->dst_ip = ip->saddr;
                item->active_time = now;
                break;
            }
        }
        {
            char src_ip_str[0x10];
            inet_ntop(AF_INET, (void *) &ip->saddr, src_ip_str, sizeof(src_ip_str));
            char nat_ip_str[0x10];
            inet_ntop(AF_INET, (void *) &nat_ip, nat_ip_str, sizeof(nat_ip_str));
            char dst_ip_str[0x10];
            inet_ntop(AF_INET, (void *) &ip->daddr, dst_ip_str, sizeof(dst_ip_str));
            printf("[SRC] %15s:%-5d -> %15s:%-5d -> %15s:%-5d\n",
                   src_ip_str, ntohs(udp->source),
                   nat_ip_str, (src_port),
                   dst_ip_str, ntohs(udp->dest));
        }
        ip->saddr = nat_ip;
        udp->source = htons(src_port);
        handled = 1;
    } else if (*queue_num == qn_dst_nat) {
        if (ip->daddr != nat_ip) goto _out;
        fwd_item *item = &fwd_table[ntohs(udp->dest)];
        if (item->active_time == 0 || now - item->active_time >= nat_timeout) goto _out;
        item->active_time = now;
        {
            char src_ip_str[0x10];
            inet_ntop(AF_INET, (void *) &ip->saddr, src_ip_str, sizeof(src_ip_str));
            char nat_ip_str[0x10];
            inet_ntop(AF_INET, (void *) &ip->daddr, nat_ip_str, sizeof(nat_ip_str));
            char dst_ip_str[0x10];
            inet_ntop(AF_INET, (void *) &item->dst_ip, dst_ip_str, sizeof(dst_ip_str));
            printf("[DST] %15s:%-5d -> %15s:%-5d -> %15s:%-5d\n",
                   src_ip_str, ntohs(udp->source),
                   nat_ip_str, ntohs(udp->dest),
                   dst_ip_str, ntohs(item->dst_port));
        }
        ip->daddr = item->dst_ip;
        udp->dest = item->dst_port;
        handled = 1;
    }

    if (handled) {
        ip->check = 0;
        ip->check = checksum(0, (unsigned short *) ip, ip->ihl << 2u);
        udp->check = 0;
        udp->check = checksum_tcpudp_ipv4(ip);
    }

    _out:
    return nfq_set_verdict2(qh, id, handled ? NF_ACCEPT : NF_REPEAT, fw_mark, (uint32_t) data_len,
                            (const unsigned char *) pkt);
}

static int nfq_setup(uint16_t *queue_num) {
    int ret = 0;
    struct nfq_handle *h;
    struct nfq_q_handle *qh = NULL;
    int fd;
    int rv;
    uint8_t buf[4096] __attribute__((aligned));
    if (!(h = nfq_open())) goto _fail;
    if (nfq_unbind_pf(h, AF_INET) < 0) goto _fail;
    if (nfq_bind_pf(h, AF_INET) < 0) goto _fail;
    if (!(qh = nfq_create_queue(h, *queue_num, (nfq_callback *) nfq_cb, (void *) queue_num))) goto _fail;
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) goto _fail;
    fd = nfq_fd(h);
    while ((rv = recv(fd, buf, sizeof(buf), 0))) nfq_handle_packet(h, (char *) (buf), rv);

    _cleanup:
    if (qh) nfq_destroy_queue(qh);
    nfq_close(h);
    return ret;

    _fail:
    ret = 1;
    goto _cleanup;
}

int write_pid(char *pid_file) {
    int ret = 0;
    int fd;
    size_t len;
    struct flock lock;
    if ((fd = open(pid_file, O_RDWR | O_CREAT, 0666)) < 0)
        goto _fail;
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    if (fcntl(fd, F_SETLK, &lock) < 0)
        goto _fail;
    char pid_str[12];
    sprintf(pid_str, "%d\n", getpid());
    len = strlen(pid_str);
    if (write(fd, pid_str, len) != len)
        goto _fail;

    _cleanup:
    free(pid_file);
    return ret;

    _fail:
    if (fd >= 0)
        close(fd);
    ret = 1;
    goto _cleanup;
}

int main(int argc, char *argv[]) {
    printf("ConeNATd %s %s\n\n", __DATE__, __TIME__);
    uint8_t opt_mark = 0x0;
    char *pid_file = NULL;
    int foreground = 0;
    int ch;
    while ((ch = getopt(argc, argv, "n:s:d:t:m:p:f")) != -1) {
        switch (ch) {
            case 'n':
                nat_ip = inet_addr(optarg);
                opt_mark |= 1u;
                break;
            case 's':
                qn_src_nat = atol(optarg);
                opt_mark |= 1u << 1u;
                break;
            case 'd':
                qn_dst_nat = atol(optarg);
                opt_mark |= 1u << 2u;
                break;
            case 't':
                nat_timeout = atol(optarg);
                break;
            case 'm':
                fw_mark = atol(optarg);
                if (!fw_mark) {
                    printf("fw_mark should not be zero!\n");
                    goto _fail;
                }
                opt_mark |= 1u << 3u;
                break;
            case 'p':
                pid_file = strdup(optarg);
                break;
            case 'f':
                foreground = 1;
                break;
            default:
                break;
        }
    }
    if (opt_mark != 0xf) {
        printf("usage: conenatd -n <src-nat-ip> -s <src-nat-queue-num> -d <dst-nat-queue-num> -m <fw-mark> [-t <nat-timeout>] [-p <pid-file>] [-f foreground]\n");
        return 0;
    }
    {
        char nat_ip_str[0x10];
        inet_ntop(AF_INET, (void *) &nat_ip, nat_ip_str, sizeof(nat_ip_str));
        printf("nat-ip=%s, src-nat-queue=%d, dst-nat-queue=%d, fw_mark=%d\n", nat_ip_str, qn_src_nat, qn_dst_nat,
               fw_mark);
    }
    if (!foreground && daemon(1, 1) < 0) {
        printf("daemon() fail\n");
        goto _fail;
    }
    if (pid_file && write_pid(pid_file)) {
        printf("write_pid() fail\n");
        goto _fail;
    }

    memset(fwd_table, 0, sizeof(fwd_table));
    srandom(time(NULL));

    pthread_t th_src_nat, th_dst_nat;
    pthread_create(&th_src_nat, NULL, (void *(*)(void *)) nfq_setup, &qn_src_nat);
    pthread_create(&th_dst_nat, NULL, (void *(*)(void *)) nfq_setup, &qn_dst_nat);
    printf("Running...\n");
    void *_not_interested;
    pthread_join(th_src_nat, &_not_interested);
    pthread_join(th_dst_nat, &_not_interested);
    _fail:
    printf("Something went wrong. Bye, world!\n");
    return 1;
}
