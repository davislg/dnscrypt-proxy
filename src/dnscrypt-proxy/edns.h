
#ifndef __EDNS_H__
#define __EDNS_H__ 1

#include <sys/types.h>

#include <stdint.h>
#include <stdlib.h>

#include "dnscrypt_proxy.h"

#define OPENDNS_DEVICE_ID_SIZE 8U
#define OPENDNS_DEVICE_ID_PREFIX_LEN (sizeof "OpenDNS" - (size_t) 1U)

#define OPENDNS_DEVICE_ID_OPTION_CODE 4U

int edns_add_section(ProxyContext * const proxy_context,
                     uint8_t * const dns_packet,
                     size_t * const dns_packet_len_p,
                     size_t dns_packet_max_size,
                     size_t * const request_edns_payload_size,
                     uint8_t const device_id[OPENDNS_DEVICE_ID_SIZE]);

#endif
