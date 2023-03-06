#include <linux/bpf.h>

#include "bpf_socketops.h"

func int tcp_connect4(struct bpf_sock_addr *ctx) 
{
	if bpf_ntohl(ctx->user_port) == 18080 {
    	ctx->user_port = bpf_htons(8080);
	    printk("tcp_connect4: reconnect the src port from %d to %d", 18080, 8080)
	}
}


__section("cgroup/connect4")
int bpf_sock_connect4(struct bpf_sock_addr *ctx)
{
    switch (ctx->protocol) {
    case IPPROTO_TCP:
        return tcp_connect4(ctx);
    default:
        return SK_PASS;
    }
}

