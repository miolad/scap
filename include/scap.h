#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <netinet/in.h>

/**
 * Arguments for Scap initialization
 */
typedef struct ScapArgs {
  /**
   * Size of the ringbuf map to move captured traffic from the
   * kernel eBPF probes to the user-space controller
   */
  uint32_t ringbuf_size;
} ScapArgs;

typedef enum FfiAddr_Tag {
  V4,
  V6,
} FfiAddr_Tag;

typedef struct FfiAddr {
  FfiAddr_Tag tag;
  union {
    struct {
      in_addr v4;
    };
    struct {
      in6_addr v6;
    };
  };
} FfiAddr;

/**
 * FFI-compatible metadata for intercepted socket messages
 */
typedef struct FfiMsgMeta {
  /**
   * Local IP address
   */
  struct FfiAddr laddr;
  /**
   * Remote IP address
   */
  struct FfiAddr raddr;
  /**
   * Local port in native byte order
   */
  uint16_t lport;
  /**
   * Remote port in native byte order
   */
  uint16_t rport;
  /**
   * Socket's Address Family, either `AF_INET` for IPv4 or `AF_INET6` for IPv6.
   * Note that dual stack sockets will be marked as AF_INET6 but can carry IPv4 traffic, too.
   */
  uint16_t af;
} FfiMsgMeta;

/**
 * Initializes the capture session.
 *
 * ## Arguments
 *  - `args`: various initialization arguments. See [ScapArgs] for additional documentation
 *  - `data_cbk`: Callback to be invoked for all new intercepted socket messages
 *
 * ## Returns
 * An opaque context pointer, or NULL in case of errors.
 * Pass the context to [scap_release] to cleanly cleanup.
 */
void *scap_init(struct ScapArgs args,
                void (*data_cbk)(struct FfiMsgMeta, uintptr_t, const uint8_t*));

/**
 * Releases a Scap context previously produced by [scap_init].
 *
 * ## Arguments
 *  - `ctx`: An opaque pointer previously returned by [scap_init]
 *
 * ## Safety
 * `ctx` must have been previosly returned by a call to [scap_init]
 */
void scap_release(void *ctx);
