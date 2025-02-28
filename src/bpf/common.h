#include "vmlinux.h"

#define AF_INET 	2
#define AF_INET6	10

union scap_addr {
	struct in6_addr in6;
	struct in_addr in;
};

struct scap_msg {
	u32 size;
	union scap_addr laddr;
	union scap_addr raddr;
	u16 lport;
	u16 rport;
	u16 af;

	u8 data[];
};
