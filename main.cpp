//
//  main.c
//  ConeNATd
//
//  Created by Chileung Law on 2020/4/6.
//  Copyright © 2020 Chileung Law. All rights reserved.
//

#include <arpa/inet.h>
#include <fcntl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include <unordered_map>
#include <map>
#include <set>
#include <thread>
#include <mutex>

using namespace std;

typedef struct {
    int fd;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint16_t nat_port;
    uint8_t seen_reply;
    time_t active_time;
} fwd_item;

fwd_item dnat_table[0x10000];
# ifdef HASH
struct pair_hash {
    template<class T1, class T2>
    size_t operator()(const pair<T1, T2> &p) const {
        return hash<T1>{}(p.first) ^ hash<T2>{}(p.first);
    }
};
unordered_map<pair<uint32_t, uint16_t>, fwd_item *, pair_hash> snat_table;
# else
map<pair<uint32_t, uint16_t>, fwd_item *> snat_table;
# endif

uint32_t nat_ip;
uint32_t fw_mark;
uint16_t new_timeout = 60;
uint16_t stream_timeout = 300;
uint16_t min_port = 1024;
uint16_t max_port = 65535;
bool foreground = false;

set<uint16_t> snat_qn;
set<uint16_t> dnat_qn;

mutex mtx;

static uint16_t update_check16(uint16_t check, uint16_t old_val, uint16_t new_val) {
    uint32_t x = (~check & 0xffffu) + (~old_val & 0xffffu) + new_val;
    x = (x >> 16u) + (x & 0xffffu);
    return ~(x + (x >> 16u));
}

static uint16_t update_check32(uint16_t check, uint32_t old_val, uint32_t new_val) {
    check = update_check16(check, old_val >> 16u, new_val >> 16u);
    check = update_check16(check, old_val & 0xffffu, new_val & 0xffffu);
    return check;
}

static int bind_port(uint16_t port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = nat_ip;
    if (bind(fd, (const sockaddr *) &sa, sizeof(sa)) < 0) {
        close(fd);
        return 0;
    }
    return fd;
}

static int nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, const uint16_t *queue_num) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    bool handled = false;
    uint32_t id = 0;
    if (ph) id = ntohl(ph->packet_id);

    time_t now = time(nullptr);
    void *pkt;
    int data_len = nfq_get_payload(nfa, (unsigned char **) &pkt);
    auto *ip = (struct iphdr *) pkt;
    auto *udp = (struct udphdr *) ((uint8_t *) ip + (ip->ihl << 2u));
    if (ip->protocol != IPPROTO_UDP) goto _out;
    if (snat_qn.find(*queue_num) != snat_qn.end()) {
        mtx.lock();
        uint16_t src_port = 0;
        auto pr = make_pair(ip->saddr, udp->source);
        if (snat_table.find(pr) != snat_table.end()) {
            auto *x = snat_table[pr];
            x->active_time = now;
            src_port = x->nat_port;
        }
        if (src_port == 0) {
            fwd_item *item = nullptr;
            set<uint16_t> visit_port;
            for (int i = 0; i < (max_port - min_port); ++i) {
                do {
                    src_port = min_port + (random() % (max_port - min_port + 1));
                } while (visit_port.find(src_port) != visit_port.end());
                visit_port.insert(src_port);
                item = &dnat_table[src_port];

                // Try to reserve the port
                int fd = bind_port(src_port);
                if (fd) {
                    item->fd = fd;
                    break;
                }

                item = nullptr;
            }
            if (item == nullptr) {
                if (foreground) printf("All ports are used!\n");
                mtx.unlock();
                goto _out;
            }
            item->dst_ip = ip->saddr;
            item->dst_port = udp->source;
            item->nat_port = src_port;
            item->active_time = now;
            item->seen_reply = 0;
            snat_table[make_pair(item->dst_ip, item->dst_port)] = item;

            if (foreground) {
                char src_ip_str[0x10];
                inet_ntop(AF_INET, (void *) &ip->saddr, src_ip_str, sizeof(src_ip_str));
                char nat_ip_str[0x10];
                inet_ntop(AF_INET, (void *) &nat_ip, nat_ip_str, sizeof(nat_ip_str));
                char dst_ip_str[0x10];
                inet_ntop(AF_INET, (void *) &ip->daddr, dst_ip_str, sizeof(dst_ip_str));
                printf("[NEW] %15s:%-5d -> %15s:%-5d -> %15s:%-5d\n",
                       src_ip_str, ntohs(udp->source),
                       nat_ip_str, src_port,
                       dst_ip_str, ntohs(udp->dest)
                );
            }
        }
        mtx.unlock();
        src_port = htons(src_port);

        ip->check = update_check32(ip->check, ip->saddr, nat_ip);
        udp->check = update_check32(udp->check, ip->saddr, nat_ip);
        udp->check = update_check16(udp->check, udp->source, src_port);
        ip->saddr = nat_ip;
        udp->source = src_port;

        handled = true;
    } else if (dnat_qn.find(*queue_num) != dnat_qn.end()) {
        if (ip->daddr != nat_ip) goto _out;
        fwd_item *item = &dnat_table[ntohs(udp->dest)];
        if ((item->active_time == 0) ||
            ((item->seen_reply == 0 && now - item->active_time >= new_timeout) ||
             (item->seen_reply == 1 && now - item->active_time >= stream_timeout)))
            goto _out;
        item->active_time = now;
        if (foreground && item->seen_reply == 0) {
            char src_ip_str[0x10];
            inet_ntop(AF_INET, (void *) &ip->saddr, src_ip_str, sizeof(src_ip_str));
            char nat_ip_str[0x10];
            inet_ntop(AF_INET, (void *) &ip->daddr, nat_ip_str, sizeof(nat_ip_str));
            char dst_ip_str[0x10];
            inet_ntop(AF_INET, (void *) &item->dst_ip, dst_ip_str, sizeof(dst_ip_str));
            printf("[EST] %15s:%-5d -> %15s:%-5d -> %15s:%-5d\n",
                   src_ip_str, ntohs(udp->source),
                   nat_ip_str, ntohs(udp->dest),
                   dst_ip_str, ntohs(item->dst_port)
            );
        }
        item->seen_reply = 1;

        ip->check = update_check32(ip->check, ip->daddr, item->dst_ip);
        udp->check = update_check32(udp->check, ip->daddr, item->dst_ip);
        udp->check = update_check16(udp->check, udp->dest, item->dst_port);
        ip->daddr = item->dst_ip;
        udp->dest = item->dst_port;

        handled = true;
    }
    _out:
    return nfq_set_verdict2(qh, id, handled ? NF_ACCEPT : NF_REPEAT, fw_mark, (uint32_t) data_len,
                            (const unsigned char *) pkt);
}

static void nfq_setup(uint16_t queue_num) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh = nullptr;
    static uint8_t buf[0x10000];
    if (!(h = nfq_open())) throw "nfq_open";
    if (nfq_unbind_pf(h, AF_INET) < 0) throw "nfq_unbind_pf";
    if (nfq_bind_pf(h, AF_INET) < 0) throw "nfq_bind_pf";
    if (!(qh = nfq_create_queue(h, queue_num, (nfq_callback *) nfq_cb, (void *) &queue_num))) throw "nfq_create_queue";
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) throw "nfq_set_mode";
    nfq_set_queue_maxlen(qh, 0x10000);
    int fd = nfq_fd(h);
    for (int n; (n = recv(fd, buf, sizeof(buf), 0));) {
        if (n > 0) nfq_handle_packet(h, (char *) buf, n);
        else if (foreground) perror("recv");
    }
    nfq_destroy_queue(qh);
    nfq_close(h);
}

void write_pid(char *pid_file) {
    bool ret = false;
    int fd;
    size_t len;
    struct flock lock{};
    if ((fd = open(pid_file, O_RDWR | O_CREAT, 0666)) < 0) throw "open";
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    if (fcntl(fd, F_SETLK, &lock) < 0) throw "fcntl";
    char pid_str[12];
    sprintf(pid_str, "%d\n", getpid());
    len = strlen(pid_str);
    if (write(fd, pid_str, len) != len) throw "write";
}

int main(int argc, char *argv[]) {
    try {
        uint16_t qn_src_nat = 0, qn_dst_nat = 0;
        printf("ConeNATd %s %s\n\n", __DATE__, __TIME__);
        uint8_t opt_mark = 0x0;
        char *pid_file = nullptr;
        int ch;
        while ((ch = getopt(argc, argv, "n:s:d:i:x:t:o:m:p:f")) != -1) {
            switch (ch) {
                case 'n':
                    nat_ip = inet_addr(optarg);
                    opt_mark |= 1u;
                    break;
                case 's':
                    qn_src_nat = stol(optarg);
                    opt_mark |= 1u << 1u;
                    break;
                case 'd':
                    qn_dst_nat = stol(optarg);
                    opt_mark |= 1u << 2u;
                    break;
                case 'i':
                    min_port = stol(optarg);
                    break;
                case 'x':
                    max_port = stol(optarg);
                    break;
                case 't':
                    new_timeout = stol(optarg);
                    break;
                case 'o':
                    stream_timeout = stol(optarg);
                    break;
                case 'm':
                    fw_mark = stol(optarg);
                    if (!fw_mark) throw "fw_mark should not be zero!";
                    opt_mark |= 1u << 3u;
                    break;
                case 'p':
                    pid_file = strdup(optarg);
                    break;
                case 'f':
                    foreground = true;
                    break;
                default:
                    break;
            }
        }
        if (opt_mark != 0xf) {
            printf("usage: conenatd -n <src-nat-ip> -s <src-nat-queue-num> -d <dst-nat-queue-num> -m <fw-mark> [-i <min-port>] [-x <max-port>] [-t <new-timeout>] [-o <stream-timeout>] [-p <pid-file>] [-f foreground]\n");
            return 0;
        }
        if (min_port >= max_port) throw "Invalid port range!";

        if (!foreground && daemon(1, 1) < 0) throw "daemon";

        {
            char nat_ip_str[0x10];
            inet_ntop(AF_INET, (void *) &nat_ip, nat_ip_str, sizeof(nat_ip_str));
            printf("nat-ip=%s, src-nat-queue=%d, dst-nat-queue=%d, min-port=%d, max-port=%d, fw_mark=%d, new-timeout=%d, stream-timeout=%d\n",
                   nat_ip_str,
                   qn_src_nat,
                   qn_dst_nat,
                   min_port,
                   max_port,
                   fw_mark,
                   new_timeout,
                   stream_timeout
            );
        }
        if (pid_file) write_pid(pid_file);

        memset(dnat_table, 0, sizeof(dnat_table));
        srandom(time(nullptr));

        // TODO: Multi-thread
        for (int i = 0; i < 1; ++i) {
            snat_qn.insert(qn_src_nat);
            thread(nfq_setup, qn_src_nat++).detach();
            dnat_qn.insert(qn_dst_nat);
            thread(nfq_setup, qn_dst_nat++).detach();
        }

        printf("Running...\n");
        while (true) {
            time_t now = time(nullptr);
            mtx.lock();
            for (auto it = snat_table.begin(); it != snat_table.end();) {
                fwd_item *item = (*it).second;
                if ((item->active_time) &&
                    (item->seen_reply == 0 && now - item->active_time >= new_timeout) ||
                    (item->seen_reply == 1 && now - item->active_time >= stream_timeout)) {
                    if (foreground) {
                        char src_ip_str[0x10];
                        inet_ntop(AF_INET, (void *) &item->dst_ip, src_ip_str, sizeof(src_ip_str));
                        char nat_ip_str[0x10];
                        inet_ntop(AF_INET, (void *) &nat_ip, nat_ip_str, sizeof(nat_ip_str));
                        printf("[DEL] %15s:%-5d <> %15s:%-5d\n",
                               src_ip_str, ntohs(item->dst_port),
                               nat_ip_str, item->nat_port
                        );
                    }
                    close(item->fd);
                    it = snat_table.erase(it);
                    continue;
                }
                ++it;
            }
            mtx.unlock();
            sleep(1);
        }
    } catch (const char *msg) {
        printf("%s\n", msg);
    }
    return 1;
}
