#include <linux/bpf.h>
#include <linux/in.h>

#include "bpf_socketops.h"

int tcp_connect4(struct bpf_sock_addr *ctx) 
{
	// rewrite the port from x.x.x.x:18080 to 127.0.0.1:8080
	if (bpf_ntohl(ctx->user_port) >> 16 == 18080) {
    	ctx->user_port = bpf_htons(8080);
        ctx->user_ip4 = localhost;
	    printk("tcp_connect4: reconnect the src port from %d to %d\n", 18080, 8080);
	}
	return SK_PASS;
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

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
