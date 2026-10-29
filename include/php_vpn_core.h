/*
 * C interface of the Rust core (core/crates/vpn-ffi). Keep in sync with
 * core/crates/vpn-ffi/src/lib.rs.
 *
 * Strings are pointer + length and not NUL-terminated unless stated. Objects
 * returned by the core are released only with the matching *_free function.
 */
#ifndef PHP_VPN_CORE_H
#define PHP_VPN_CORE_H

#include <stddef.h>
#include <stdint.h>

#define VPN_ERROR_MESSAGE_SIZE 512

/* Values of vpn_error.code; also the PHP exception codes. */
#define VPN_E_INTERNAL 1
#define VPN_E_CONFIG 2
#define VPN_E_TUNNEL 3
#define VPN_E_DNS 4
#define VPN_E_CONNECT 5
#define VPN_E_TLS 6
#define VPN_E_TIMEOUT 7
#define VPN_E_PROTOCOL 8
#define VPN_E_POLICY 9
#define VPN_E_LIMIT 10
#define VPN_E_LOCK_TIMEOUT 11

typedef struct vpn_profile vpn_profile;
typedef struct vpn_response vpn_response;

typedef struct {
	int32_t code; /* 0 on success */
	char message[VPN_ERROR_MESSAGE_SIZE]; /* NUL-terminated */
} vpn_error;

typedef struct {
	const uint8_t *ptr;
	size_t len;
} vpn_str;

typedef struct {
	vpn_str name;
	vpn_str value;
} vpn_header;

typedef struct {
	vpn_str method;
	vpn_str url;
	const vpn_header *headers;
	size_t headers_len;
	vpn_str body;
	double timeout;
	double connect_timeout;
	uint32_t max_redirects;
	uint8_t verify_tls;
	uint8_t allow_private;
	uint8_t allow_https_downgrade;
	uint8_t decode_content;
	vpn_str ca_file; /* empty = bundled Mozilla roots */
	uint64_t max_response_size;
} vpn_request_spec;

typedef struct {
	vpn_str lock_dir; /* empty = system temporary directory */
	double session_ttl;
	uint32_t max_tunnels;
} vpn_settings;

const char *vpn_version(void); /* NUL-terminated, static */

vpn_profile *vpn_profile_from_file(vpn_str path, uint8_t enforce_permissions, vpn_error *err);
vpn_profile *vpn_profile_from_string(vpn_str config, vpn_error *err);
vpn_profile *vpn_profile_pool(const vpn_profile *const *members, size_t count, vpn_error *err);
void vpn_profile_free(vpn_profile *profile);
size_t vpn_profile_member_count(const vpn_profile *profile);
void vpn_profile_close(const vpn_profile *profile);
char *vpn_profile_info_json(const vpn_profile *profile); /* free with vpn_string_free */
void vpn_string_free(char *s);

vpn_response *vpn_request(const vpn_profile *profile, const vpn_request_spec *spec,
	const vpn_settings *settings, vpn_error *err);
uint16_t vpn_response_status(const vpn_response *r);
vpn_str vpn_response_body(const vpn_response *r);
vpn_str vpn_response_url(const vpn_response *r);
vpn_str vpn_response_remote_ip(const vpn_response *r);
uint32_t vpn_response_redirects(const vpn_response *r);
size_t vpn_response_header_count(const vpn_response *r);
int vpn_response_header(const vpn_response *r, size_t index, vpn_str *name, vpn_str *value);
void vpn_response_free(vpn_response *r);

#endif
