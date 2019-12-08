//
//  conenatd.c
//  ConeNATd
//
//  Created by Chileung Law on 2019/12/6.
//  Copyright © 2019 Chileung Law. All rights reserved.
//

#include <arpa/inet.h>
#include <fcntl.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef struct {
    uint32_t dst_ip;
    uint16_t dst_port;
    uint16_t ref;
} fwd_item;
fwd_item fwd_table[0x10000];

uint32_t nat_ip;
uint32_t queue_num;
uint32_t fwmark;

uint16_t checksum(uint32_t sum, uint16_t* buf, int size)
{
    while (size > 1) {
        sum += *buf++;
        size -= sizeof(uint16_t);
    }
    if (size)
        sum += *(uint8_t*)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

uint16_t checksum_tcpudp_ipv4(struct iphdr* iph)
{
    uint32_t sum = 0;
    uint32_t iph_len = iph->ihl * 4;
    uint32_t len = ntohs(iph->tot_len) - iph_len;
    uint8_t* payload = (uint8_t*)iph + iph_len;
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += (iph->saddr) & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += (iph->daddr) & 0xFFFF;
    sum += htons(iph->protocol);
    sum += htons(len);
    return checksum(sum, (uint16_t*)payload, len);
}

int ct_create(uint32_t src_ip, uint16_t src_port, uint16_t nat_port, uint32_t dst_ip, uint16_t dst_port)
{
    int xret = 0;
    struct mnl_socket* nl;
    struct nlmsghdr* nlh;
    struct nfgenmsg* nfh;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    unsigned int seq, portid;
    struct nf_conntrack* ct;
    int ret;

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL)
        goto _fail;
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
        goto _fail;
    portid = mnl_socket_get_portid(nl);

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    nlh->nlmsg_seq = seq = time(NULL);

    nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
    nfh->nfgen_family = AF_INET;
    nfh->version = NFNETLINK_V0;
    nfh->res_id = 0;

    if (!(ct = nfct_new()))
        goto _fail;

    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_UDP);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, 60);

    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, src_ip);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, src_port);

    nfct_set_attr_u32(ct, ATTR_IPV4_DST, nat_ip);
    nfct_set_attr_u16(ct, ATTR_PORT_DST, nat_port);

    nfct_set_attr_u32(ct, ATTR_DNAT_IPV4, dst_ip);
    nfct_set_attr_u16(ct, ATTR_DNAT_PORT, dst_port);

    nfct_set_attr_u32(ct, ATTR_SNAT_IPV4, nat_ip);
    nfct_set_attr_u16(ct, ATTR_SNAT_PORT, src_port);

    nfct_setobjopt(ct, NFCT_SOPT_SETUP_REPLY);
    nfct_nlmsg_build(nlh, ct);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) == -1)
        goto _fail;
    while (1) {
        int recv_size;
        if ((recv_size = mnl_socket_recvfrom(nl, buf, sizeof(buf))) == -1)
            goto _fail;
        if ((ret = mnl_cb_run(buf, recv_size, seq, portid, NULL, NULL)) <= MNL_CB_STOP)
            break;
    }
    if (ret == -1)
        goto _fail;
    else
        ret = 0;
_cleanup:
    if (nl)
        mnl_socket_close(nl);
    return ret;
_fail:
    ret = 1;
    goto _cleanup;
}

static int nfq_cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* data)
{
    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    int handled = 0;
    uint32_t id = 0;
    if (ph)
        id = ntohl(ph->packet_id);
    int data_len = nfq_get_payload(nfa, (unsigned char**)&data);
    struct iphdr* iph = (struct iphdr*)data;
    if (iph->protocol != IPPROTO_UDP)
        goto _out;
    if (iph->daddr != nat_ip)
        goto _out;
    struct udphdr* uh = (struct udphdr*)((uint8_t*)iph + (iph->ihl << 2));
    fwd_item* item = &fwd_table[uh->dest];
    {
        char src_ip_str[0x10];
        inet_ntop(AF_INET, (void*)&iph->saddr, src_ip_str, sizeof(src_ip_str));
        char nat_ip_str[0x10];
        inet_ntop(AF_INET, (void*)&iph->daddr, nat_ip_str, sizeof(nat_ip_str));
        char dst_ip_str[0x10];
        inet_ntop(AF_INET, (void*)&item->dst_ip, dst_ip_str, sizeof(dst_ip_str));
        printf("[!] %5s %15s:%-5d -> %15s:%-5d -> %15s:%-5d\n",
            item->ref ? "FWD" : "IGN",
            src_ip_str, ntohs(uh->source),
            nat_ip_str, ntohs(uh->dest),
            dst_ip_str, ntohs(item->dst_port));
    }
    if (!item->ref)
        goto _out;
    if (ct_create(iph->saddr, uh->source, uh->dest, item->dst_ip, item->dst_port)) {
        printf("ct_create() fail\n");
    }
    iph->daddr = item->dst_ip;
    uh->dest = item->dst_port;
    iph->check = 0;
    iph->check = checksum(0, (unsigned short*)iph, iph->ihl << 2);
    uh->check = 0;
    uh->check = checksum_tcpudp_ipv4(iph);
    handled = 1;
_out:
    return nfq_set_verdict2(qh, id, handled ? NF_ACCEPT : NF_REPEAT, fwmark, (uint32_t)data_len, data);
}

static int nfq_setup()
{
    int ret = 0;
    struct nfq_handle* h;
    struct nfq_q_handle* qh = NULL;
    int fd;
    int rv;
    uint8_t buf[4096] __attribute__((aligned));
    if (!(h = nfq_open()))
        goto _fail;
    if (nfq_unbind_pf(h, AF_INET) < 0)
        goto _fail;
    if (nfq_bind_pf(h, AF_INET) < 0)
        goto _fail;
    if (!(qh = nfq_create_queue(h, queue_num, nfq_cb, NULL)))
        goto _fail;
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
        goto _fail;
    fd = nfq_fd(h);
    while ((rv = recv(fd, buf, sizeof(buf), 0)))
        nfq_handle_packet(h, buf, rv);
_cleanup:
    if (qh)
        nfq_destroy_queue(qh);
    nfq_close(h);
    return ret;
_fail:
    ret = 1;
    goto _cleanup;
}

static int ct_cb(const struct nlmsghdr* nlh, void* data)
{
    struct nf_conntrack* ct;
    uint32_t type = NFCT_T_UNKNOWN;

    switch (nlh->nlmsg_type & 0xFF) {
    case IPCTNL_MSG_CT_NEW:
        if (nlh->nlmsg_flags & (NLM_F_CREATE | NLM_F_EXCL))
            type = NFCT_T_NEW;
        else
            type = NFCT_T_UPDATE;
        break;
    case IPCTNL_MSG_CT_DELETE:
        type = NFCT_T_DESTROY;
        break;
    }
    ct = nfct_new();
    if (!ct)
        goto _cleanup;
    nfct_nlmsg_parse(nlh, ct);

    if (!(nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT) == 1 && nfct_getobjopt(ct, NFCT_GOPT_IS_DNAT) == 0))
        goto _cleanup;
    if (nfct_get_attr_u8(ct, ATTR_L4PROTO) != IPPROTO_UDP)
        goto _cleanup;

    uint32_t src_ip = nfct_get_attr_u32(ct, ATTR_IPV4_SRC);
    uint16_t src_port = nfct_get_attr_u16(ct, ATTR_PORT_SRC);
    uint32_t dst_ip = nfct_get_attr_u32(ct, ATTR_IPV4_DST);
    uint16_t dst_port = nfct_get_attr_u16(ct, ATTR_PORT_DST);
    uint32_t repl_src_ip = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC);
    uint16_t repl_src_port = nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC);
    uint32_t repl_dst_ip = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST);
    uint16_t repl_dst_port = nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST);

    if (src_ip == repl_dst_ip && src_port == repl_dst_port && dst_ip == repl_src_ip && dst_port == repl_src_port)
        goto _cleanup;
    if (repl_dst_ip != nat_ip)
        goto _cleanup;

    fwd_item* item = &fwd_table[repl_dst_port];
    switch (type) {
    case NFCT_T_NEW:
        if (!(nlh->nlmsg_flags & (NLM_F_CREATE | NLM_F_EXCL)))
            break;
        item->dst_ip = src_ip;
        item->dst_port = src_port;
        ++item->ref;
        {
            char nat_ip_str[0x10];
            inet_ntop(AF_INET, (void*)&repl_dst_ip, nat_ip_str, sizeof(nat_ip_str));
            char dst_ip_str[0x10];
            inet_ntop(AF_INET, (void*)&src_ip, dst_ip_str, sizeof(dst_ip_str));
            printf("[+] %5d %15s:%-5d -> %15s:%-5d\n",
                item->ref,
                nat_ip_str, ntohs(repl_dst_port),
                dst_ip_str, ntohs(src_port));
        }
        break;
    case NFCT_T_DESTROY:
        if (!item->ref)
            break;
        if (!--item->ref)
            memset(item, 0, sizeof(fwd_item));
        {
            char nat_ip_str[0x10];
            inet_ntop(AF_INET, (void*)&repl_dst_ip, nat_ip_str, sizeof(nat_ip_str));
            char dst_ip_str[0x10];
            inet_ntop(AF_INET, (void*)&src_ip, dst_ip_str, sizeof(dst_ip_str));
            printf("[-] %5d %15s:%-5d -> %15s:%-5d\n",
                item->ref,
                nat_ip_str, ntohs(repl_dst_port),
                dst_ip_str, ntohs(src_port));
        }
        break;
    }

_cleanup:
    if (ct)
        nfct_destroy(ct);
    return MNL_CB_OK;
}

static int ct_setup()
{
    int ret = 0;
    struct mnl_socket* nl;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    if (!(nl = mnl_socket_open(NETLINK_NETFILTER)))
        goto _fail;
    if (mnl_socket_bind(
            nl,
            NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_DESTROY,
            MNL_SOCKET_AUTOPID)
        < 0)
        goto _fail;
    while (1) {
        int recv_size;
        if ((recv_size = mnl_socket_recvfrom(nl, buf, sizeof(buf))) == -1)
            goto _fail;
        if (mnl_cb_run(buf, recv_size, 0, 0, ct_cb, NULL) == -1)
            goto _fail;
    }
_cleanup:
    if (nl)
        mnl_socket_close(nl);
    return ret;
_fail:
    ret = 1;
    goto _cleanup;
}

int write_pid(char* pid_file)
{
    int ret = 0;
    int fd;
    if ((fd = open(pid_file, O_RDWR | O_CREAT, 0666)) < 0)
        goto _fail;
    struct flock lock;
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    if (fcntl(fd, F_SETLK, &lock) < 0)
        goto _fail;
    char pid_str[12];
    sprintf(pid_str, "%d\n", getpid());
    int len = strlen(pid_str);
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

int main(int argc, char* argv[])
{
    printf("ConeNATd %s %s\n\n", __DATE__, __TIME__);
    uint8_t optmark = 0x0;
    char* pid_file = NULL;
    int foreground = 0;
    int ch;
    while ((ch = getopt(argc, argv, "n:q:m:p:f")) != -1) {
        switch (ch) {
        case 'n':
            nat_ip = inet_addr(optarg);
            optmark |= 0x1;
            break;
        case 'q':
            queue_num = atol(optarg);
            optmark |= 0x2;
            break;
        case 'm':
            fwmark = atol(optarg);
            if (!fwmark) {
                printf("fwmark should not be zero!\n");
                goto _fail;
            }
            optmark |= 0x4;
            break;
        case 'p':
            pid_file = strdup(optarg);
            break;
        case 'f':
            foreground = 1;
            break;
        }
    }
    if (optmark != 0x7) {
        printf("usage: conenatd -n <nat-ip> -q <queue-num> -m <fwmark> [-p <pid-file>] [-f foreground]\n");
        return 0;
    }
    {
        char nat_ip_str[0x10];
        inet_ntop(AF_INET, (void*)&nat_ip, nat_ip_str, sizeof(nat_ip_str));
        printf("nat-ip=%s, queue-num=%d, fwmark=%d\n", nat_ip_str, queue_num, fwmark);
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
    pthread_t pth_ct;
    pthread_create(&pth_ct, NULL, (void* (*)(void*))ct_setup, NULL);
    pthread_t pth_nfq;
    pthread_create(&pth_nfq, NULL, (void* (*)(void*))nfq_setup, NULL);
    printf("Running...\n");
    void* _not_interested;
    pthread_join(pth_ct, &_not_interested);
    goto _fail;
    pthread_join(pth_nfq, &_not_interested);
_fail:
    printf("Something went wrong. Bye, world!\n");
    return 1;
}
