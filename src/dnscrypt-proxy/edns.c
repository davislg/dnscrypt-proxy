
#include <config.h>
#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dnscrypt_proxy.h"
#include "edns.h"
#include "utils.h"

static int
_skip_name(const uint8_t * const dns_packet, const size_t dns_packet_len,
           size_t * const offset_p)
{
    size_t  offset = *offset_p;
    uint8_t name_component_len;

    if (dns_packet_len < (size_t) 1U ||
        offset >= dns_packet_len - (size_t) 1U) {
        return -1;
    }
    do {
        name_component_len = dns_packet[offset];
        if ((name_component_len & 0xC0) == 0xC0) {
            name_component_len = 1U;
        }
        if (name_component_len >= dns_packet_len - offset - 1U) {
            return -1;
        }
        offset += name_component_len + 1U;
    } while (name_component_len != 0U);
    if (offset >= dns_packet_len) {
        return -1;
    }
    *offset_p = offset;

    return 0;
}

#define DNS_QTYPE_PLUS_QCLASS_LEN 4U

static ssize_t
edns_get_payload_size(const uint8_t * const dns_packet,
                      const size_t dns_packet_len)
{
    size_t       offset;
    size_t       payload_size;
    unsigned int arcount;

    assert(dns_packet_len >= DNS_HEADER_SIZE);
    arcount = (dns_packet[DNS_OFFSET_ARCOUNT] << 8) |
        dns_packet[DNS_OFFSET_ARCOUNT + 1U];
    assert(arcount > 0U);
    assert(DNS_OFFSET_QUESTION <= DNS_HEADER_SIZE);
    if (dns_packet[DNS_OFFSET_QDCOUNT] != 0U ||
        dns_packet[DNS_OFFSET_QDCOUNT + 1U] != 1U ||
        (dns_packet[DNS_OFFSET_ANCOUNT] |
         dns_packet[DNS_OFFSET_ANCOUNT + 1U]) != 0U ||
        (dns_packet[DNS_OFFSET_NSCOUNT] |
         dns_packet[DNS_OFFSET_NSCOUNT + 1U]) != 0U) {
        return (ssize_t) -1;
    }
    offset = DNS_OFFSET_QUESTION;
    if (_skip_name(dns_packet, dns_packet_len, &offset) != 0) {
        return (ssize_t) -1;
    }
    assert(dns_packet_len > (size_t) DNS_QTYPE_PLUS_QCLASS_LEN);
    if (offset >= dns_packet_len - (size_t) DNS_QTYPE_PLUS_QCLASS_LEN) {
        return (ssize_t) -1;
    }
    offset += DNS_QTYPE_PLUS_QCLASS_LEN;
    assert(dns_packet_len >= DNS_OFFSET_EDNS_PAYLOAD_SIZE + 2U);
    if (_skip_name(dns_packet, dns_packet_len, &offset) != 0 ||
        offset >= dns_packet_len - DNS_OFFSET_EDNS_PAYLOAD_SIZE - 2U) {
        return (ssize_t) -1;
    }
    assert(DNS_OFFSET_EDNS_PAYLOAD_SIZE > DNS_OFFSET_EDNS_TYPE);
    if (dns_packet[offset + DNS_OFFSET_EDNS_TYPE] != 0U ||
        dns_packet[offset + DNS_OFFSET_EDNS_TYPE + 1U] != DNS_TYPE_OPT) {
        return (ssize_t) -1;
    }
    payload_size = (dns_packet[offset + DNS_OFFSET_EDNS_PAYLOAD_SIZE] << 8) |
        dns_packet[offset + DNS_OFFSET_EDNS_PAYLOAD_SIZE + 1U];
    if (payload_size < DNS_MAX_PACKET_SIZE_UDP_SEND) {
        payload_size = DNS_MAX_PACKET_SIZE_UDP_SEND;
    }
    return (ssize_t) payload_size;
}

static void
_add_opendns_device_id(uint8_t opt_rr[], const size_t opt_rr_size,
                       uint8_t const opendns_device_id[OPENDNS_DEVICE_ID_SIZE],
                       size_t * const opt_rr_len_p)
{
    *opt_rr_len_p = 1U + DNS_OFFSET_EDNS_DATA + DNS_OFFSET_EDNS_OPTION_DATA +
        OPENDNS_DEVICE_ID_PREFIX_LEN + OPENDNS_DEVICE_ID_SIZE;
    assert(opt_rr_size == *opt_rr_len_p);
    memcpy(&opt_rr[1U + DNS_OFFSET_EDNS_DATA + DNS_OFFSET_EDNS_OPTION_DATA +
                   OPENDNS_DEVICE_ID_PREFIX_LEN],
           opendns_device_id, OPENDNS_DEVICE_ID_SIZE);

    assert(1U + DNS_OFFSET_EDNS_DATA + DNS_OFFSET_EDNS_OPTION_CODE + 1U
           < *opt_rr_len_p);
    opt_rr[1U + DNS_OFFSET_EDNS_DATA + DNS_OFFSET_EDNS_OPTION_CODE] =
        (OPENDNS_DEVICE_ID_OPTION_CODE >> 8) & 0xFF;
    opt_rr[1U + DNS_OFFSET_EDNS_DATA + DNS_OFFSET_EDNS_OPTION_CODE + 1U] =
        OPENDNS_DEVICE_ID_OPTION_CODE & 0xFF;

    assert(1U + DNS_OFFSET_EDNS_DATA + DNS_OFFSET_EDNS_OPTION_LENGTH + 1U
           < *opt_rr_len_p);
    opt_rr[1U + DNS_OFFSET_EDNS_DATA + DNS_OFFSET_EDNS_OPTION_LENGTH] =
        ((OPENDNS_DEVICE_ID_PREFIX_LEN + OPENDNS_DEVICE_ID_SIZE) >> 8) & 0xFF;
    opt_rr[1U + DNS_OFFSET_EDNS_DATA + DNS_OFFSET_EDNS_OPTION_LENGTH + 1U] =
        (OPENDNS_DEVICE_ID_PREFIX_LEN + OPENDNS_DEVICE_ID_SIZE) & 0xFF;

    assert(1U + DNS_OFFSET_EDNS_RDLEN + 1U < *opt_rr_len_p);
    opt_rr[1U + DNS_OFFSET_EDNS_RDLEN] =
        ((DNS_OFFSET_EDNS_OPTION_DATA +
          OPENDNS_DEVICE_ID_PREFIX_LEN + OPENDNS_DEVICE_ID_SIZE) >> 8) & 0xFF;
    opt_rr[1U + DNS_OFFSET_EDNS_RDLEN + 1U] =
        (DNS_OFFSET_EDNS_OPTION_DATA +
            OPENDNS_DEVICE_ID_PREFIX_LEN + OPENDNS_DEVICE_ID_SIZE) & 0xFF;
}

int
edns_add_section(ProxyContext * const proxy_context,
                 uint8_t * const dns_packet, size_t * const dns_packet_len_p,
                 size_t dns_packet_max_size,
                 size_t * const request_edns_payload_size,
                 uint8_t const opendns_device_id[OPENDNS_DEVICE_ID_SIZE])
{
    const size_t edns_payload_size = proxy_context->edns_payload_size;

    assert(edns_payload_size <= (size_t) 0xFFFF);
    assert(DNS_OFFSET_ARCOUNT + 2U <= DNS_HEADER_SIZE);
    if (edns_payload_size <= DNS_MAX_PACKET_SIZE_UDP_SEND ||
        *dns_packet_len_p <= DNS_HEADER_SIZE) {
        *request_edns_payload_size = (size_t) 0U;
        return -1;
    }
    if ((dns_packet[DNS_OFFSET_ARCOUNT] |
         dns_packet[DNS_OFFSET_ARCOUNT + 1U]) != 0U) {
        const ssize_t edns_payload_ssize =
            edns_get_payload_size(dns_packet, *dns_packet_len_p);
        if (edns_payload_ssize <= (ssize_t) 0U) {
            *request_edns_payload_size = (size_t) 0U;
            return -1;
        }
        *request_edns_payload_size = (size_t) edns_payload_ssize;
        return 1;
    }
    assert(dns_packet_max_size >= *dns_packet_len_p);

    assert(DNS_OFFSET_EDNS_TYPE == 0U);
    assert(DNS_OFFSET_EDNS_PAYLOAD_SIZE == 2U);
    uint8_t opt_rr[] = {
        0U,               /* name */
        0U, DNS_TYPE_OPT, /* type */
        (edns_payload_size >> 8) & 0xFF, edns_payload_size & 0xFF,
        0U,               /* extended rcode */
        0U,               /* version */
        0U, 0U,           /* flags */
        0U, 0U,           /* rdlen */
        0U, 0U,           /* option code */
        0U, 0U,           /* option length */
        'O', 'p', 'e', 'n', 'D', 'N', 'S',
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U /* opendns_device_id */
    };
    size_t opt_rr_len = 1U + DNS_OFFSET_EDNS_DATA;
    COMPILER_ASSERT(sizeof opt_rr ==
                    1U + DNS_OFFSET_EDNS_DATA + DNS_OFFSET_EDNS_OPTION_DATA +
                    OPENDNS_DEVICE_ID_PREFIX_LEN + OPENDNS_DEVICE_ID_SIZE);
    assert(opt_rr[1U + DNS_OFFSET_EDNS_DATA + DNS_OFFSET_EDNS_OPTION_DATA]
           == (uint8_t) 'O');
    if (opendns_device_id != NULL) {
        _add_opendns_device_id(opt_rr, sizeof opt_rr,
                               opendns_device_id, &opt_rr_len);
    }
    if (dns_packet_max_size - *dns_packet_len_p < opt_rr_len) {
        *request_edns_payload_size = (size_t) 0U;
        return -1;
    }
    assert(dns_packet[DNS_OFFSET_ARCOUNT + 1U] == 0U);
    dns_packet[DNS_OFFSET_ARCOUNT + 1U] = 1U;
    memcpy(dns_packet + *dns_packet_len_p, opt_rr, opt_rr_len);
    *dns_packet_len_p += opt_rr_len;
    *request_edns_payload_size = edns_payload_size;
    assert(*dns_packet_len_p <= dns_packet_max_size);
    assert(*dns_packet_len_p <= 0xFFFF);

    return 0;
}

static int
_edns_parse_char(uint8_t opendns_device_id[OPENDNS_DEVICE_ID_SIZE],
                 size_t * const opendns_device_id_pos_p, int * const state_p,
                 const int c, uint8_t * const val_p)
{
    uint8_t c_val;

    switch (*state_p) {
    case 0:
    case 1:
        if (isspace(c) || (c == ':' && *state_p == 0)) {
            break;
        }
        if (c == '#') {
            *state_p = 2;
            break;
        }
        if (!isxdigit(c)) {
            return -1;
        }
        c_val = (c >= '0' && c <= '9') ? c - '0' : c - 'a' + 10;
        assert(c_val < 16U);
        if (*state_p == 0) {
            *val_p = c_val * 16U;
            *state_p = 1;
        } else {
            *val_p |= c_val;
            opendns_device_id[(*opendns_device_id_pos_p)++] = *val_p;
            if (*opendns_device_id_pos_p >= OPENDNS_DEVICE_ID_SIZE) {
                return 0;
            }
            *state_p = 0;
        }
    case 2:
        if (c == '\n') {
            *state_p = 0;
        }
    }
    return 1;
}

int
edns_fingerprint_to_opendns_device_id(const char * const fingerprint,
                                      uint8_t opendns_device_id[OPENDNS_DEVICE_ID_SIZE])
{
    const char *p = fingerprint;
    size_t      opendns_device_id_pos = (size_t) 0U;
    int         c;
    int         ret;
    int         state = 0;
    uint8_t     val = 0U;

    if (fingerprint == NULL) {
        return -1;
    }
    while ((c = tolower((int) (unsigned char) *p)) != 0) {
        ret = _edns_parse_char(opendns_device_id, &opendns_device_id_pos,
                               &state, c, &val);
        if (ret <= 0) {
            return ret;
        }
        p++;
    }
    return -1;
}
