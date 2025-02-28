#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

#define MAX_RB_MSG_SIZE (1 << 14)
#define MAX_IOV_SEGS	16
#define MAX_IOV_CHUNKS  16

/**
  *  sockmap: main socket map, it will contain every open socket on the system.
  */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 1); /* Will be overwritten by user-space */
} sockmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1); /* Will be overwritten by user-space */
} msg_ring SEC(".maps");

/* sock_cntr: incremental counter used as key to `sockmap` */
u64 sock_cntr = 0;

SEC("iter/tcp")
int iter_tcp(struct bpf_iter__tcp *ctx)
{
	struct sock_common *skc = ctx->sk_common;
	struct seq_file *seq = ctx->meta->seq;
	u64 key;
	long ret;

	if (!skc)
		goto out;

	if (!bpf_skc_to_tcp_sock(skc))
		goto out;

	// Bug fixed in 6.4.7
	key = __sync_fetch_and_add(&sock_cntr, 1);
	ret = bpf_map_update_elem(&sockmap, &key, skc, BPF_NOEXIST);
	bpf_printk("[skc=%p] bpf_map_update_elem returned %ld", skc, ret);

out:
	return 0;
}

SEC("sockops")
int add_established_sock(struct bpf_sock_ops *skops)
{
	int op = (int)skops->op;
	u64 key;
	long ret;

	switch (op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		key = __sync_fetch_and_add(&sock_cntr, 1);
		ret = bpf_sock_hash_update(skops, &sockmap, &key, BPF_NOEXIST);
		bpf_printk("[skops=%p] bpf_sock_hash_update returned %ld",
								skops, ret);

		break;

	default:
		break;
	}

	return 0;
}

SEC("sk_msg")
int sock_msg(struct sk_msg_md *msg)
{
	// bpf_printk("Intercepted msg with size=%lu", msg->size);
	
	return SK_PASS;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	struct sock_common *skc = &sk->__sk_common;
	struct bpf_dynptr rb_dynptr;
	struct scap_msg msg_hdr;
	uint iov_segs, iov_seg;
	long ret;

	switch (skc->skc_family) {
	case AF_INET:
		msg_hdr.laddr.in.s_addr = skc->skc_rcv_saddr;
		msg_hdr.raddr.in.s_addr = skc->skc_daddr;
		break;

	case AF_INET6:
		__builtin_memcpy(&msg_hdr.laddr.in6,
				&skc->skc_v6_rcv_saddr.in6_u.u6_addr8, 16);
		__builtin_memcpy(&msg_hdr.raddr.in6,
				&skc->skc_v6_daddr.in6_u.u6_addr8, 16);
		break;

	default:
		goto out;
	}

	msg_hdr.af    = skc->skc_family;
	msg_hdr.lport = skc->skc_num;
	msg_hdr.rport = skc->skc_dport;

	iov_segs = msg->msg_iter.nr_segs;
	iov_segs = iov_segs <= MAX_IOV_SEGS ? iov_segs : MAX_IOV_SEGS;
	for (iov_seg = 0; iov_seg < iov_segs; ++iov_seg) {
		uint chunk, chunks;
		struct iovec iov;
		void *iov_base;
		size_t iov_len;

		ret = bpf_probe_read_kernel(&iov, sizeof(struct iovec),
					&msg->msg_iter.__ubuf_iovec + iov_seg);
		if (ret) {
			bpf_printk("bpf_probe_read_kernel failed with %lu", ret);
			continue;
		}

		iov_base = iov.iov_base;
		iov_len = iov.iov_len;
		chunks = (iov_len + MAX_RB_MSG_SIZE - 1) / MAX_RB_MSG_SIZE;
		chunks = chunks <= MAX_IOV_CHUNKS ? chunks : MAX_IOV_CHUNKS;
		for (chunk = 0; chunk < chunks; ++chunk) {
			struct scap_msg *rb_msg;
			uint chunk_size = iov_len - (chunk * MAX_RB_MSG_SIZE);

			chunk_size = chunk_size <= MAX_RB_MSG_SIZE ? chunk_size : MAX_RB_MSG_SIZE;
			rb_msg = bpf_ringbuf_reserve(&msg_ring,
				sizeof(struct scap_msg) + MAX_RB_MSG_SIZE, 0);
			if (!rb_msg) {
				bpf_printk("bpf_ringbuf_reserve returned NULL");
				continue;
			}

			__builtin_memcpy(rb_msg, &msg_hdr,
						sizeof(struct scap_msg));
			rb_msg->size = chunk_size;
			ret = bpf_probe_read(rb_msg->data, chunk_size, iov_base);
			if (ret) {
				bpf_printk("bpf_probe_read failed with %lu", ret);
				goto discard;
			}

			bpf_ringbuf_submit(rb_msg, 0);
			continue;
discard:
			bpf_ringbuf_discard(rb_msg, 0);
		}
	}

out:
	return 0;
}

// SEC("raw_tp/sched_switch")
// int util_addsock(struct sock_common **ctx) {
// 	struct sock *sk = *ctx;
// 	u64 zero = 0;
	
// 	if (bpf_map_update_elem(&sockmap, &zero, sk, BPF_NOEXIST))
// 		bpf_printk("Error inserting socket into map: %p", *ctx);
// 	else
// 		bpf_printk("Socket successfully inserted into map: %p", *ctx);
	
// 	return 0;
// }

char LICENSE[] SEC("license") = "GPL";
