#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "scap.h"

// This function gets called for every captured message
void message_callback(struct FfiMsgMeta meta, uintptr_t len, const uint8_t* data)
{
	char src_addr[INET6_ADDRSTRLEN];
	char dst_addr[INET6_ADDRSTRLEN];

	if (!inet_ntop(meta.laddr.tag == V4 ? AF_INET : AF_INET6,
				&meta.laddr.v4, src_addr, INET6_ADDRSTRLEN)) {
		return;
	}
	if (!inet_ntop(meta.raddr.tag == V4 ? AF_INET : AF_INET6,
				&meta.raddr.v4, dst_addr, INET6_ADDRSTRLEN)) {
		return;
	}

	// v4 addresses end up back-to-front for some reason, v6 untested
	printf("Captured message: local=%s:%d, remote=%s:%d, len=%lu\n",
			src_addr, meta.lport, dst_addr, meta.rport, len);
}

int main()
{
	struct ScapArgs args = {
		.ringbuf_size = 1 << 22
	};
	void* scap_ctx = scap_init(args, message_callback);

	if (!scap_ctx) {
		fprintf(stderr, "Failed to initialize scap\n");
		return EXIT_FAILURE;
	}

	getchar();
	scap_release(scap_ctx);

	return EXIT_SUCCESS;
}
