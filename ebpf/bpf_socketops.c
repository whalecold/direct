#include <linux/bpf.h>

#include "bpf_socketops.h"

static inline
void extract_key4_from_ops(struct bpf_sock_ops *ops, struct sock_key *key)
{
	// keep ip and port in network byte order
	key->dip4 = ops->remote_ip4;
	key->sip4 = ops->local_ip4;
	key->family = 1;

	// local_port is in host byte order, and remote_port is in network byte order
    key->sport = (bpf_htonl(ops->local_port) >> 16);
    key->dport = FORCE_READ(ops->remote_port) >> 16;
}

static inline
void bpf_sock_ops_ipv4(struct bpf_sock_ops * skops)
{
	struct sock_key key = {};
	int ret;

	extract_key4_from_ops(skops, &key);

	ret = sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
	if (ret != 0) {
		printk("socket hash update() failed, ret %d\n", ret);
	}
	printk("sockmap: op %d, port %d  -->  %d\n", 
			skops->op, skops->local_port, bpf_ntohl(skops->remote_port));
}

__section("sockops") // 加载到 ELF 中的 `sockops` 区域，有 socket operations 时触发执行
int bpf_sockmap(struct bpf_sock_ops *skops)
{
	switch (skops->op) {
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // 被动建连
		case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:  // 主动建连
			if (skops->family == 2 && skops->remote_port == 8080) { // AF_INET 并且端口是 8080
				bpf_sock_ops_ipv4(skops);         // 将 socket 信息记录到到 sockmap
			}
			break;
		default:
			break;
	}
	return 0;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
