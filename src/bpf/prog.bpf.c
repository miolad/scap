#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

#define MAX_RB_MSG_SIZE (1 << 14)
#define MAX_IOV_SEGS	16
#define MAX_IOV_CHUNKS  16

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1); /* Will be overwritten by user-space */
} msg_ring SEC(".maps");

static inline int capture_msg(struct sock *sk, struct msghdr *msg,
							int maxlen, int dir)
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
	msg_hdr.dir   = dir;

	iov_segs = msg->msg_iter.nr_segs;
	iov_segs = iov_segs <= MAX_IOV_SEGS ? iov_segs : MAX_IOV_SEGS;
	bpf_for(iov_seg, 0, iov_segs) {
	// for (iov_seg = 0; iov_seg < iov_segs && maxlen > 0; ++iov_seg) {
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
		bpf_for(chunk, 0, chunks) {
		// for (chunk = 0; chunk < chunks; ++chunk) {
			struct scap_msg *rb_msg;
			uint chunk_size = iov_len - (chunk * MAX_RB_MSG_SIZE);

			chunk_size = chunk_size <= MAX_RB_MSG_SIZE ? chunk_size
							: MAX_RB_MSG_SIZE;
			chunk_size = chunk_size <= maxlen ? chunk_size : maxlen;
			rb_msg = bpf_ringbuf_reserve(&msg_ring,
				sizeof(struct scap_msg) + MAX_RB_MSG_SIZE, 0);
			if (!rb_msg) {
				bpf_printk("bpf_ringbuf_reserve returned NULL");
				continue;
			}

			__builtin_memcpy(rb_msg, &msg_hdr,
						sizeof(struct scap_msg));
			rb_msg->size = chunk_size;
			maxlen -= chunk_size;
			ret = bpf_probe_read(rb_msg->data, chunk_size, iov_base);
			if (ret) {
				bpf_printk("bpf_probe_read failed with %lu", ret);
				goto discard;
			}

			bpf_ringbuf_submit(rb_msg, 0);
			if (maxlen == 0) break;
			continue;
discard:
			bpf_ringbuf_discard(rb_msg, 0);
		}
		if (maxlen == 0) break;
	}

out:
	return 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	return capture_msg(sk, msg, (1 << 22), 1);
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(recvmsg, struct sock *sk, struct msghdr *msg, size_t len,
					int flags, int *addr_len, int ret)
{
	if (ret > 0)
		return capture_msg(sk, msg, ret, 0);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
