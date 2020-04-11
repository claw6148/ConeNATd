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

#define HASH

using namespace std;

typedef struct {
    int fd;
    uint32_t src_ip;
    uint16_t src_port;
    uint16_t nat_port;
    bool seen_reply = false;
    time_t active_time = 0;
} nat_item;

# ifdef HASH

struct pair_hash {
    template<class T1, class T2>
    size_t operator()(const pair<T1, T2> &p) const {
        return hash<T1>{}(p.first) ^ hash<T2>{}(p.first);
    }
};

unordered_map<pair<uint32_t, uint16_t>, nat_item *, pair_hash> src_nat_table;
unordered_map<uint16_t, nat_item> dst_nat_table;
# else
map<pair<uint32_t, uint16_t>, nat_item *> src_nat_table;
map<uint16_t, nat_item> dst_nat_table;
# endif

uint32_t nat_ip;
uint32_t fw_mark;
uint16_t new_timeout = 60;
uint16_t stream_timeout = 300;
uint16_t min_port = 1024;
uint16_t max_port = 65535;
uint16_t session_per_src_ip = 0;
bool foreground = false;

map<uint32_t, uint16_t> session_count;

mutex src_nat_mtx;
mutex dst_nat_mtx;

uint16_t src_nat_queue_num;
uint16_t dst_nat_queue_num;

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

static int nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *, struct nfq_data *nfa, const uint16_t *queue_num) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    bool nat = false;
    bool drop = false;
    bool lock_src_nat = false;
    bool lock_dst_nat = false;
    uint32_t id = 0;
    if (ph) id = ntohl(ph->packet_id);

    time_t now = time(nullptr);
    void *pkt;
    int data_len = nfq_get_payload(nfa, (unsigned char **) &pkt);
    if (data_len <= 0) goto _out;
    struct iphdr *ip;
    ip = (struct iphdr *) pkt;
    struct udphdr *udp;
    udp = (struct udphdr *) ((uint8_t *) ip + (ip->ihl << 2u));
    if (ip->protocol != IPPROTO_UDP) goto _out;
    if (*queue_num == src_nat_queue_num) {
        uint16_t nat_port = 0;
        auto pr = make_pair(ip->saddr, udp->source);
        src_nat_mtx.lock();
        lock_src_nat = true;
        if (src_nat_table.find(pr) != src_nat_table.end()) {
            auto *x = src_nat_table[pr];
            x->active_time = now;
            nat_port = x->nat_port;
        }
        if (nat_port == 0) {
            bool reach_limit = false;
            nat_item *item = nullptr;
            set<uint16_t> visit_port;
            dst_nat_mtx.lock();
            lock_dst_nat = true;
            for (int i = 0; i < (max_port - min_port); ++i) {
                do {
                    nat_port = min_port + (random() % (max_port - min_port + 1));
                } while (visit_port.find(nat_port) != visit_port.end());
                visit_port.insert(nat_port);
                item = &dst_nat_table[nat_port];

                // Check session limit
                if (session_per_src_ip) {
                    if (session_count[ip->saddr] + 1 > session_per_src_ip) {
                        item = nullptr;
                        reach_limit = true;
                        break;
                    } else {
                        ++session_count[ip->saddr];
                    }
                }

                // Try to reserve the port
                int fd = bind_port(nat_port);
                if (fd) {
                    item->fd = fd;
                    break;
                }

                item = nullptr;
            }
            if (item == nullptr) {
                if (foreground) {
                    char src_ip_str[0x10];
                    inet_ntop(AF_INET, (void *) &ip->saddr, src_ip_str, sizeof(src_ip_str));
                    printf("No port available for %s!\n", src_ip_str);
                }
                if (!reach_limit) --session_count[ip->saddr];
                drop = true;
                goto _out;
            }
            item->src_ip = ip->saddr;
            item->src_port = udp->source;
            item->nat_port = nat_port;
            item->active_time = now;
            src_nat_table[make_pair(item->src_ip, item->src_port)] = item;

            if (foreground) {
                char src_ip_str[0x10];
                inet_ntop(AF_INET, (void *) &ip->saddr, src_ip_str, sizeof(src_ip_str));
                char nat_ip_str[0x10];
                inet_ntop(AF_INET, (void *) &nat_ip, nat_ip_str, sizeof(nat_ip_str));
                char dst_ip_str[0x10];
                inet_ntop(AF_INET, (void *) &ip->daddr, dst_ip_str, sizeof(dst_ip_str));
                printf("[NEW] %15s:%-5d -> %15s:%-5d -> %15s:%-5d\n",
                       src_ip_str, ntohs(udp->source),
                       nat_ip_str, nat_port,
                       dst_ip_str, ntohs(udp->dest)
                );
            }
        }
        nat_port = htons(nat_port);

        ip->check = update_check32(ip->check, ip->saddr, nat_ip);
        udp->check = update_check32(udp->check, ip->saddr, nat_ip);
        udp->check = update_check16(udp->check, udp->source, nat_port);
        ip->saddr = nat_ip;
        udp->source = nat_port;

        nat = true;
    } else if (*queue_num == dst_nat_queue_num) {
        dst_nat_mtx.lock();
        lock_dst_nat = true;
        if (ip->daddr != nat_ip) goto _out;
        if (dst_nat_table.find(ntohs(udp->dest)) == dst_nat_table.end()) goto _out;
        nat_item *item = &dst_nat_table[ntohs(udp->dest)];
        if (item->active_time == 0 ||
            ((!item->seen_reply && now - item->active_time >= new_timeout) ||
             (item->seen_reply && now - item->active_time >= stream_timeout))) {
            drop = true;
            goto _out;
        }

        item->active_time = now;
        if (foreground && !item->seen_reply) {
            char src_ip_str[0x10];
            inet_ntop(AF_INET, (void *) &ip->saddr, src_ip_str, sizeof(src_ip_str));
            char nat_ip_str[0x10];
            inet_ntop(AF_INET, (void *) &ip->daddr, nat_ip_str, sizeof(nat_ip_str));
            char dst_ip_str[0x10];
            inet_ntop(AF_INET, (void *) &item->src_ip, dst_ip_str, sizeof(dst_ip_str));
            printf("[EST] %15s:%-5d -> %15s:%-5d -> %15s:%-5d\n",
                   src_ip_str, ntohs(udp->source),
                   nat_ip_str, ntohs(udp->dest),
                   dst_ip_str, ntohs(item->src_port)
            );
        }
        item->seen_reply = true;

        ip->check = update_check32(ip->check, ip->daddr, item->src_ip);
        udp->check = update_check32(udp->check, ip->daddr, item->src_ip);
        udp->check = update_check16(udp->check, udp->dest, item->src_port);
        ip->daddr = item->src_ip;
        udp->dest = item->src_port;

        nat = true;
    }
    _out:
    if (lock_src_nat) src_nat_mtx.unlock();
    if (lock_dst_nat) dst_nat_mtx.unlock();
    return nfq_set_verdict2(
            qh,
            id,
            nat ? NF_ACCEPT : drop ? NF_DROP : NF_REPEAT,
            fw_mark,
            nat ? data_len : 0,
            nat ? (const unsigned char *) pkt : nullptr
    );
}

static void nfq_setup(uint16_t queue_num) {
    try {
        struct nfq_handle *h;
        struct nfq_q_handle *qh = nullptr;
        static uint8_t buf[0x10000];
        if (!(h = nfq_open())) throw "nfq_open";
        if (nfq_unbind_pf(h, AF_INET) < 0) throw "nfq_unbind_pf";
        if (nfq_bind_pf(h, AF_INET) < 0) throw "nfq_bind_pf";
        if (!(qh = nfq_create_queue(h, queue_num, (nfq_callback *) nfq_cb, (void *) &queue_num)))
            throw "nfq_create_queue";
        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) throw "nfq_set_mode";
        nfq_set_queue_maxlen(qh, 0x1000 << 2u);
        int fd = nfq_fd(h);
        for (int n; (n = recv(fd, buf, sizeof(buf), 0));) {
            if (n > 0) nfq_handle_packet(h, (char *) buf, n);
            else if (foreground) perror("recv");
        }
        nfq_destroy_queue(qh);
        nfq_close(h);
    } catch (const char *msg) {
        if (errno) perror(msg);
        else fprintf(stderr, "%s\n", msg);
        exit(1);
    }
}

void write_pid(char *pid_file) {
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
        printf("ConeNATd %s %s\n\n", __DATE__, __TIME__);
        uint8_t opt_mark = 0x0;
        char *pid_file = nullptr;
        int ch;
        while ((ch = getopt(argc, argv, "n:s:d:i:x:t:o:e:m:p:f")) != -1) {
            switch (ch) {
                case 'n':
                    nat_ip = inet_addr(optarg);
                    opt_mark |= 1u;
                    break;
                case 's':
                    src_nat_queue_num = stol(optarg);
                    opt_mark |= 1u << 1u;
                    break;
                case 'd':
                    dst_nat_queue_num = stol(optarg);
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
                case 'e':
                    session_per_src_ip = stol(optarg);
                    break;
                case 'm':
                    fw_mark = stol(optarg);
                    if (!fw_mark) throw "The fw-mark should not be zero!";
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
            printf(
                    "Usage: conenatd\n"
                    "  -n <src-nat-ip>\n"
                    "  -s <src-nat-queue-num>\n"
                    "  -d <dst-nat-queue-num>\n"
                    "  -m <fw-mark>\n"
                    "  [-y <nat-type> (WIP)]\n"
                    "  [-i <min-port>]\n"
                    "  [-x <max-port>]\n"
                    "  [-t <new-timeout>]\n"
                    "  [-o <stream-timeout>]\n"
                    "  [-e <session-per-src-ip>]\n"
                    "  [-p <pid-file>]\n"
                    "  [-f foreground]\n"
            );
            return 0;
        }
        if (min_port >= max_port) throw "Invalid port range!";

        if (!foreground && daemon(1, 1) < 0) throw "daemon";

        {
            char nat_ip_str[0x10];
            inet_ntop(AF_INET, (void *) &nat_ip, nat_ip_str, sizeof(nat_ip_str));
            printf(
                    "src-nat-ip=%s\n"
                    "src-nat-queue-num=%d\n"
                    "dst-nat-queue-num=%d\n"
                    "fw-mark=%d\n"
                    "min-port=%d\n"
                    "max-port=%d\n"
                    "new-timeout=%d\n"
                    "stream-timeout=%d\n"
                    "session-per-src-ip=%d\n"
                    "\n",
                    nat_ip_str,
                    src_nat_queue_num,
                    dst_nat_queue_num,
                    fw_mark,
                    min_port,
                    max_port,
                    new_timeout,
                    stream_timeout,
                    session_per_src_ip
            );
        }
        if (pid_file) write_pid(pid_file);

        srandom(time(nullptr));

        thread(nfq_setup, src_nat_queue_num).detach();
        thread(nfq_setup, dst_nat_queue_num).detach();

        printf("Running...\n");
        while (true) {
            time_t now = time(nullptr);
            src_nat_mtx.lock();
            for (auto it = src_nat_table.begin(); it != src_nat_table.end();) {
                nat_item *item = (*it).second;
                if (item->active_time &&
                    ((!item->seen_reply && now - item->active_time >= new_timeout) ||
                     (item->seen_reply && now - item->active_time >= stream_timeout))) {
                    if (foreground) {
                        char src_ip_str[0x10];
                        inet_ntop(AF_INET, (void *) &item->src_ip, src_ip_str, sizeof(src_ip_str));
                        char nat_ip_str[0x10];
                        inet_ntop(AF_INET, (void *) &nat_ip, nat_ip_str, sizeof(nat_ip_str));
                        printf("[DEL] %15s:%-5d <> %15s:%-5d\n",
                               src_ip_str, ntohs(item->src_port),
                               nat_ip_str, item->nat_port
                        );
                    }
                    if (session_per_src_ip) {
                        if (--session_count[item->src_ip] <= 0)
                            session_count.erase(item->src_ip);
                    }
                    close(item->fd);

                    dst_nat_mtx.lock();
                    dst_nat_table.erase(item->nat_port);
                    dst_nat_mtx.unlock();

                    it = src_nat_table.erase(it);
                    continue;
                }
                ++it;
            }
            src_nat_mtx.unlock();
            sleep(1);
        }
    } catch (const char *msg) {
        if (errno) perror(msg);
        else fprintf(stderr, "%s\n", msg);
        exit(1);
    }
}
