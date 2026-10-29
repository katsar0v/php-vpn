/*
 * php-vpn: send selected HTTP(S) requests through a userspace WireGuard
 * tunnel. This file is the PHP-facing layer; the tunnel, TCP/IP stack, DNS,
 * TLS and HTTP live in the Rust core (include/php_vpn_core.h).
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/standard/php_string.h"
#include "ext/json/php_json.h"
#include "ext/spl/spl_exceptions.h"
#include "zend_attributes.h"
#include "zend_exceptions.h"
#include "zend_interfaces.h"
#include "zend_smart_str.h"

#include "php_vpn.h"
#include "php_vpn_core.h"
#include "vpn_arginfo.h"

ZEND_DECLARE_MODULE_GLOBALS(vpn)

#define PHP_VPN_MAX_POOL 64
#define PHP_VPN_MAX_REDIRECTS 50

static zend_class_entry *php_vpn_ce;
static zend_class_entry *php_vpn_response_ce;
/* Indexed by VPN_E_* code; [VPN_E_INTERNAL] is the base VPN\Exception. */
static zend_class_entry *php_vpn_exception_ce[VPN_E_LOCK_TIMEOUT + 1];

static zend_object_handlers php_vpn_handlers;
static zend_object_handlers php_vpn_response_handlers;

/* {{{ INI */
PHP_INI_BEGIN()
	STD_PHP_INI_ENTRY("php_vpn.default_timeout", "30", PHP_INI_ALL, OnUpdateReal, default_timeout, zend_vpn_globals, vpn_globals)
	STD_PHP_INI_ENTRY("php_vpn.connect_timeout", "10", PHP_INI_ALL, OnUpdateReal, connect_timeout, zend_vpn_globals, vpn_globals)
	STD_PHP_INI_ENTRY("php_vpn.max_response_size", "16M", PHP_INI_ALL, OnUpdateLong, max_response_size, zend_vpn_globals, vpn_globals)
	STD_PHP_INI_ENTRY("php_vpn.max_redirects", "5", PHP_INI_ALL, OnUpdateLong, max_redirects, zend_vpn_globals, vpn_globals)
	STD_PHP_INI_ENTRY("php_vpn.ca_file", "", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateString, ca_file, zend_vpn_globals, vpn_globals)
	STD_PHP_INI_BOOLEAN("php_vpn.allow_private_destinations", "0", PHP_INI_ALL, OnUpdateBool, allow_private_destinations, zend_vpn_globals, vpn_globals)
	STD_PHP_INI_ENTRY("php_vpn.lock_dir", "", PHP_INI_SYSTEM, OnUpdateString, lock_dir, zend_vpn_globals, vpn_globals)
	STD_PHP_INI_ENTRY("php_vpn.session_ttl", "120", PHP_INI_SYSTEM, OnUpdateLong, session_ttl, zend_vpn_globals, vpn_globals)
	STD_PHP_INI_ENTRY("php_vpn.max_tunnels", "4", PHP_INI_SYSTEM, OnUpdateLong, max_tunnels, zend_vpn_globals, vpn_globals)
	STD_PHP_INI_ENTRY("php_vpn.allowed_config_dir", "", PHP_INI_SYSTEM, OnUpdateString, allowed_config_dir, zend_vpn_globals, vpn_globals)
	STD_PHP_INI_BOOLEAN("php_vpn.enforce_key_permissions", "1", PHP_INI_SYSTEM, OnUpdateBool, enforce_key_permissions, zend_vpn_globals, vpn_globals)
PHP_INI_END()
/* }}} */

/* {{{ objects */
typedef struct {
	vpn_profile *profile;
	zval defaults; /* default request options, or UNDEF */
	zend_object std;
} php_vpn_object;

typedef struct {
	zend_long status;
	zend_long redirects;
	zend_string *body;
	zend_string *url;
	zend_string *remote;
	zval headers; /* array<string, list<string>> */
	zend_object std;
} php_vpn_response_object;

static inline php_vpn_object *php_vpn_fetch(zend_object *obj)
{
	return (php_vpn_object *)((char *)obj - offsetof(php_vpn_object, std));
}

static inline php_vpn_response_object *php_vpn_response_fetch(zend_object *obj)
{
	return (php_vpn_response_object *)((char *)obj - offsetof(php_vpn_response_object, std));
}

static zend_object *php_vpn_create(zend_class_entry *ce)
{
	php_vpn_object *o = zend_object_alloc(sizeof(php_vpn_object), ce);

	zend_object_std_init(&o->std, ce);
	object_properties_init(&o->std, ce);
	o->std.handlers = &php_vpn_handlers;
	o->profile = NULL;
	ZVAL_UNDEF(&o->defaults);
	return &o->std;
}

static void php_vpn_free(zend_object *obj)
{
	php_vpn_object *o = php_vpn_fetch(obj);

	if (o->profile) {
		vpn_profile_free(o->profile);
		o->profile = NULL;
	}
	zval_ptr_dtor(&o->defaults);
	zend_object_std_dtor(obj);
}

static zend_object *php_vpn_response_create(zend_class_entry *ce)
{
	php_vpn_response_object *r = zend_object_alloc(sizeof(php_vpn_response_object), ce);

	zend_object_std_init(&r->std, ce);
	object_properties_init(&r->std, ce);
	r->std.handlers = &php_vpn_response_handlers;
	r->status = 0;
	r->redirects = 0;
	r->body = NULL;
	r->url = NULL;
	r->remote = NULL;
	array_init(&r->headers);
	return &r->std;
}

static void php_vpn_response_free(zend_object *obj)
{
	php_vpn_response_object *r = php_vpn_response_fetch(obj);

	if (r->body) {
		zend_string_release(r->body);
	}
	if (r->url) {
		zend_string_release(r->url);
	}
	if (r->remote) {
		zend_string_release(r->remote);
	}
	zval_ptr_dtor(&r->headers);
	zend_object_std_dtor(obj);
}

/* var_dump()/print_r() of a response: everything except the body itself. */
static HashTable *php_vpn_response_debug_info(zend_object *obj, int *is_temp)
{
	php_vpn_response_object *r = php_vpn_response_fetch(obj);
	HashTable *ht = zend_new_array(4);
	zval tmp;

	*is_temp = 1;
	ZVAL_LONG(&tmp, r->status);
	zend_hash_str_update(ht, "status", sizeof("status") - 1, &tmp);
	if (r->url) {
		ZVAL_STR_COPY(&tmp, r->url);
		zend_hash_str_update(ht, "effectiveUrl", sizeof("effectiveUrl") - 1, &tmp);
	}
	ZVAL_COPY(&tmp, &r->headers);
	zend_hash_str_update(ht, "headers", sizeof("headers") - 1, &tmp);
	ZVAL_LONG(&tmp, r->body ? (zend_long)ZSTR_LEN(r->body) : 0);
	zend_hash_str_update(ht, "bodyLength", sizeof("bodyLength") - 1, &tmp);
	return ht;
}
/* }}} */

/* {{{ helpers */
static inline vpn_str php_vpn_str(const char *ptr, size_t len)
{
	vpn_str s;
	s.ptr = (const uint8_t *)ptr;
	s.len = len;
	return s;
}

static zend_class_entry *php_vpn_exception_for(int code)
{
	if (code > 0 && code <= VPN_E_LOCK_TIMEOUT && php_vpn_exception_ce[code]) {
		return php_vpn_exception_ce[code];
	}
	return php_vpn_exception_ce[VPN_E_INTERNAL];
}

static void php_vpn_throw_error(const vpn_error *err)
{
	zend_throw_exception(php_vpn_exception_for(err->code), err->message, err->code);
}

static void php_vpn_throw(int code, const char *format, ...) ZEND_ATTRIBUTE_FORMAT(printf, 2, 3);

static void php_vpn_throw(int code, const char *format, ...)
{
	va_list args;
	char *message;

	va_start(args, format);
	zend_vspprintf(&message, 0, format, args);
	va_end(args);
	zend_throw_exception(php_vpn_exception_for(code), message, code);
	efree(message);
}

/* Whether `resolved` lies inside one of the php_vpn.allowed_config_dir entries. */
static bool php_vpn_path_allowed(const char *resolved)
{
	const char *list = VPN_G(allowed_config_dir);
	const char separator[2] = { ZEND_PATHS_SEPARATOR, '\0' };
	char *copy, *dir, *state = NULL;
	bool ok = false;

	if (!list || !*list) {
		return true;
	}
	copy = estrdup(list);
	for (dir = php_strtok_r(copy, separator, &state); dir; dir = php_strtok_r(NULL, separator, &state)) {
		char real_dir[MAXPATHLEN];
		size_t n;

		if (!*dir || !VCWD_REALPATH(dir, real_dir)) {
			continue;
		}
		n = strlen(real_dir);
		while (n > 1 && real_dir[n - 1] == '/') {
			real_dir[--n] = '\0';
		}
		if (strncmp(resolved, real_dir, n) == 0 && (resolved[n] == '/' || (n == 1 && real_dir[0] == '/'))) {
			ok = true;
			break;
		}
	}
	efree(copy);
	return ok;
}

/* Paths are echoed in error messages, except when the "path" is clearly
 * something else - typically profile contents passed to wireguard() instead
 * of wireguardFromString() - which may contain a private key. */
static const char *php_vpn_shown_path(const char *path, size_t len)
{
	size_t i, run = 0;

	if (len > 1024) {
		return "(not shown)";
	}
	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)path[i];

		if (c < 0x20 || c == 0x7f) {
			return "(invalid path)";
		}
		/* 43+ base64 characters in a row could be a key. */
		run = (isalnum(c) || c == '+' || c == '/' || c == '=') ? run + 1 : 0;
		if (run >= 43) {
			return "(not shown)";
		}
	}
	return path;
}

/* Resolves a user-supplied path to a regular file and applies open_basedir. */
static bool php_vpn_resolve_path(const char *path, size_t len, const char *what, char *resolved)
{
	zend_stat_t st;
	const char *shown;

	if (len == 0 || strlen(path) != len) {
		php_vpn_throw(VPN_E_CONFIG, "%s path must be a non-empty string without NUL bytes", what);
		return false;
	}
	shown = php_vpn_shown_path(path, len);
	if (!VCWD_REALPATH(path, resolved)) {
		php_vpn_throw(VPN_E_CONFIG, "%s `%s` cannot be opened: %s", what, shown, strerror(errno));
		return false;
	}
	if (php_check_open_basedir_ex(resolved, 0)) {
		php_vpn_throw(VPN_E_CONFIG, "%s `%s` is outside open_basedir", what, shown);
		return false;
	}
	/* Checked before anything opens it: a FIFO would block forever. */
	if (VCWD_STAT(resolved, &st) != 0 || !S_ISREG(st.st_mode)) {
		php_vpn_throw(VPN_E_CONFIG, "%s `%s` is not a regular file", what, shown);
		return false;
	}
	return true;
}

static vpn_profile *php_vpn_load_file(const char *path, size_t len)
{
	char resolved[MAXPATHLEN];
	vpn_error err;
	vpn_profile *profile;

	if (!php_vpn_resolve_path(path, len, "WireGuard profile", resolved)) {
		return NULL;
	}
	if (!php_vpn_path_allowed(resolved)) {
		php_vpn_throw(VPN_E_CONFIG, "WireGuard profile `%s` is outside php_vpn.allowed_config_dir", php_vpn_shown_path(path, len));
		return NULL;
	}
	profile = vpn_profile_from_file(php_vpn_str(resolved, strlen(resolved)), VPN_G(enforce_key_permissions) ? 1 : 0, &err);
	if (!profile) {
		php_vpn_throw_error(&err);
	}
	return profile;
}
/* }}} */

/* {{{ request options */
typedef struct {
	vpn_request_spec spec;
	HashTable *request_headers;
	HashTable *default_headers;
	vpn_header *headers;
	size_t headers_len;
	size_t headers_cap;
	HashTable strings; /* keeps converted strings alive until the call returns */
	char ca_file[MAXPATHLEN];
} php_vpn_request;

static void php_vpn_request_init(php_vpn_request *req)
{
	const char *ca = VPN_G(ca_file);
	zend_long redirects = VPN_G(max_redirects);
	zend_long max_size = VPN_G(max_response_size);

	memset(req, 0, sizeof(*req));
	zend_hash_init(&req->strings, 8, NULL, ZVAL_PTR_DTOR, 0);
	req->spec.timeout = VPN_G(default_timeout);
	req->spec.connect_timeout = VPN_G(connect_timeout);
	req->spec.max_redirects = (uint32_t)(redirects < 0 ? 0 : MIN(redirects, PHP_VPN_MAX_REDIRECTS));
	req->spec.verify_tls = 1;
	req->spec.allow_private = VPN_G(allow_private_destinations) ? 1 : 0;
	req->spec.allow_https_downgrade = 0;
	req->spec.decode_content = 1;
	req->spec.max_response_size = max_size > 0 ? (uint64_t)max_size : 16 * 1024 * 1024;
	if (ca && *ca) {
		req->spec.ca_file = php_vpn_str(ca, strlen(ca));
	}
}

static void php_vpn_request_dtor(php_vpn_request *req)
{
	if (req->headers) {
		efree(req->headers);
	}
	zend_hash_destroy(&req->strings);
}

/* Converts a scalar to a string kept alive in req->strings. */
static zend_string *php_vpn_keep_string(php_vpn_request *req, zval *value)
{
	zval tmp;

	ZVAL_STR(&tmp, zval_get_string(value));
	zend_hash_next_index_insert(&req->strings, &tmp);
	return Z_STR(tmp);
}

static zend_string *php_vpn_keep_raw(php_vpn_request *req, const char *ptr, size_t len)
{
	zval tmp;

	ZVAL_STRINGL(&tmp, ptr, len);
	zend_hash_next_index_insert(&req->strings, &tmp);
	return Z_STR(tmp);
}

static bool php_vpn_option_seconds(zval *v, const char *name, double *out)
{
	double d;

	ZVAL_DEREF(v);
	if (Z_TYPE_P(v) == IS_LONG) {
		d = (double)Z_LVAL_P(v);
	} else if (Z_TYPE_P(v) == IS_DOUBLE) {
		d = Z_DVAL_P(v);
	} else {
		php_vpn_throw(VPN_E_CONFIG, "option `%s` must be a number of seconds, %s given", name, zend_zval_type_name(v));
		return false;
	}
	if (!(d > 0) || d > 86400) {
		php_vpn_throw(VPN_E_CONFIG, "option `%s` must be greater than 0 and at most 86400", name);
		return false;
	}
	*out = d;
	return true;
}

static bool php_vpn_option_bool(zval *v, const char *name, uint8_t *out)
{
	ZVAL_DEREF(v);
	if (Z_TYPE_P(v) != IS_TRUE && Z_TYPE_P(v) != IS_FALSE) {
		php_vpn_throw(VPN_E_CONFIG, "option `%s` must be a bool, %s given", name, zend_zval_type_name(v));
		return false;
	}
	*out = Z_TYPE_P(v) == IS_TRUE ? 1 : 0;
	return true;
}

/* Applies one options array; request-level options override defaults. */
static bool php_vpn_apply_options(php_vpn_request *req, HashTable *options, bool is_request)
{
	zend_string *key;
	zend_ulong idx;
	zval *v;

	ZEND_HASH_FOREACH_KEY_VAL(options, idx, key, v) {
		(void)idx;
		if (!key) {
			php_vpn_throw(VPN_E_CONFIG, "options must be an array with string keys");
			return false;
		}
		ZVAL_DEREF(v);
		if (zend_string_equals_literal(key, "headers")) {
			if (Z_TYPE_P(v) != IS_ARRAY) {
				php_vpn_throw(VPN_E_CONFIG, "option `headers` must be an array");
				return false;
			}
			if (is_request) {
				req->request_headers = Z_ARRVAL_P(v);
			} else {
				req->default_headers = Z_ARRVAL_P(v);
			}
		} else if (zend_string_equals_literal(key, "body")) {
			if (Z_TYPE_P(v) == IS_NULL) {
				req->spec.body = php_vpn_str(NULL, 0);
			} else if (Z_TYPE_P(v) == IS_STRING) {
				req->spec.body = php_vpn_str(Z_STRVAL_P(v), Z_STRLEN_P(v));
			} else {
				php_vpn_throw(VPN_E_CONFIG, "option `body` must be a string (use http_build_query() or json_encode()), %s given", zend_zval_type_name(v));
				return false;
			}
		} else if (zend_string_equals_literal(key, "timeout")) {
			if (!php_vpn_option_seconds(v, "timeout", &req->spec.timeout)) {
				return false;
			}
		} else if (zend_string_equals_literal(key, "connect_timeout")) {
			if (!php_vpn_option_seconds(v, "connect_timeout", &req->spec.connect_timeout)) {
				return false;
			}
		} else if (zend_string_equals_literal(key, "follow_redirects")) {
			if (Z_TYPE_P(v) == IS_FALSE) {
				req->spec.max_redirects = 0;
			} else if (Z_TYPE_P(v) == IS_TRUE) {
				zend_long r = VPN_G(max_redirects);
				req->spec.max_redirects = (uint32_t)(r <= 0 ? 5 : MIN(r, PHP_VPN_MAX_REDIRECTS));
			} else if (Z_TYPE_P(v) == IS_LONG && Z_LVAL_P(v) >= 0 && Z_LVAL_P(v) <= PHP_VPN_MAX_REDIRECTS) {
				req->spec.max_redirects = (uint32_t)Z_LVAL_P(v);
			} else {
				php_vpn_throw(VPN_E_CONFIG, "option `follow_redirects` must be a bool or an int between 0 and %d", PHP_VPN_MAX_REDIRECTS);
				return false;
			}
		} else if (zend_string_equals_literal(key, "verify_tls")) {
			if (!php_vpn_option_bool(v, "verify_tls", &req->spec.verify_tls)) {
				return false;
			}
		} else if (zend_string_equals_literal(key, "allow_private")) {
			if (!php_vpn_option_bool(v, "allow_private", &req->spec.allow_private)) {
				return false;
			}
		} else if (zend_string_equals_literal(key, "allow_https_downgrade")) {
			if (!php_vpn_option_bool(v, "allow_https_downgrade", &req->spec.allow_https_downgrade)) {
				return false;
			}
		} else if (zend_string_equals_literal(key, "decode_content")) {
			if (!php_vpn_option_bool(v, "decode_content", &req->spec.decode_content)) {
				return false;
			}
		} else if (zend_string_equals_literal(key, "ca_file")) {
			if (Z_TYPE_P(v) == IS_NULL) {
				const char *ca = VPN_G(ca_file);
				req->spec.ca_file = php_vpn_str(ca ? ca : "", ca ? strlen(ca) : 0);
			} else if (Z_TYPE_P(v) == IS_STRING) {
				if (!php_vpn_resolve_path(Z_STRVAL_P(v), Z_STRLEN_P(v), "ca_file", req->ca_file)) {
					return false;
				}
				req->spec.ca_file = php_vpn_str(req->ca_file, strlen(req->ca_file));
			} else {
				php_vpn_throw(VPN_E_CONFIG, "option `ca_file` must be a string or null");
				return false;
			}
		} else if (zend_string_equals_literal(key, "max_response_size")) {
			if (Z_TYPE_P(v) != IS_LONG || Z_LVAL_P(v) <= 0) {
				php_vpn_throw(VPN_E_CONFIG, "option `max_response_size` must be a positive int");
				return false;
			}
			req->spec.max_response_size = (uint64_t)Z_LVAL_P(v);
		} else {
			php_vpn_throw(VPN_E_CONFIG, "unknown option `%s`", ZSTR_VAL(key));
			return false;
		}
	} ZEND_HASH_FOREACH_END();
	return true;
}

static void php_vpn_push_header(php_vpn_request *req, const char *name, size_t name_len, const char *value, size_t value_len)
{
	if (req->headers_len == req->headers_cap) {
		req->headers_cap = req->headers_cap ? req->headers_cap * 2 : 8;
		req->headers = safe_erealloc(req->headers, req->headers_cap, sizeof(vpn_header), 0);
	}
	req->headers[req->headers_len].name = php_vpn_str(name, name_len);
	req->headers[req->headers_len].value = php_vpn_str(value, value_len);
	req->headers_len++;
}

static bool php_vpn_header_seen(HashTable *seen, const char *name, size_t len)
{
	zend_string *tmp = zend_string_init(name, len, 0);
	zend_string *lower = zend_string_tolower(tmp);
	bool found = zend_hash_exists(seen, lower);

	zend_string_release(tmp);
	zend_string_release(lower);
	return found;
}

static void php_vpn_header_mark(HashTable *seen, const char *name, size_t len)
{
	zend_string *tmp = zend_string_init(name, len, 0);
	zend_string *lower = zend_string_tolower(tmp);

	zend_string_release(tmp);
	zend_hash_add_empty_element(seen, lower);
	zend_string_release(lower);
}

/* Appends the headers of one array. Accepts ['Name' => 'value'],
 * ['Name' => ['v1', 'v2']] and ['Name: value']. With `skip`, names already in
 * `seen` are left out (request headers replace default headers). */
static bool php_vpn_collect_headers(php_vpn_request *req, HashTable *headers, HashTable *seen, bool skip, bool mark)
{
	zend_string *key;
	zval *v;

	ZEND_HASH_FOREACH_STR_KEY_VAL(headers, key, v) {
		const char *name;
		size_t name_len;

		ZVAL_DEREF(v);
		if (key) {
			name = ZSTR_VAL(key);
			name_len = ZSTR_LEN(key);
			if (skip && php_vpn_header_seen(seen, name, name_len)) {
				continue;
			}
			if (Z_TYPE_P(v) == IS_ARRAY) {
				zval *item;
				ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(v), item) {
					zend_string *s;
					ZVAL_DEREF(item);
					if (Z_TYPE_P(item) == IS_ARRAY || Z_TYPE_P(item) == IS_OBJECT) {
						php_vpn_throw(VPN_E_CONFIG, "header `%s` values must be scalars", name);
						return false;
					}
					s = php_vpn_keep_string(req, item);
					php_vpn_push_header(req, name, name_len, ZSTR_VAL(s), ZSTR_LEN(s));
				} ZEND_HASH_FOREACH_END();
			} else if (Z_TYPE_P(v) == IS_OBJECT) {
				php_vpn_throw(VPN_E_CONFIG, "header `%s` value must be a scalar", name);
				return false;
			} else {
				zend_string *s = php_vpn_keep_string(req, v);
				php_vpn_push_header(req, name, name_len, ZSTR_VAL(s), ZSTR_LEN(s));
			}
		} else {
			const char *colon;
			const char *value;
			size_t value_len;
			zend_string *n;

			if (Z_TYPE_P(v) != IS_STRING || !(colon = memchr(Z_STRVAL_P(v), ':', Z_STRLEN_P(v)))) {
				php_vpn_throw(VPN_E_CONFIG, "headers without a key must be strings like `Name: value`");
				return false;
			}
			name = Z_STRVAL_P(v);
			name_len = (size_t)(colon - name);
			while (name_len && (name[name_len - 1] == ' ' || name[name_len - 1] == '\t')) {
				name_len--;
			}
			value = colon + 1;
			value_len = Z_STRLEN_P(v) - (size_t)(value - name);
			while (value_len && (*value == ' ' || *value == '\t')) {
				value++;
				value_len--;
			}
			if (skip && php_vpn_header_seen(seen, name, name_len)) {
				continue;
			}
			n = php_vpn_keep_raw(req, name, name_len);
			php_vpn_push_header(req, ZSTR_VAL(n), ZSTR_LEN(n), value, value_len);
			name = ZSTR_VAL(n);
		}
		if (mark) {
			php_vpn_header_mark(seen, name, name_len);
		}
	} ZEND_HASH_FOREACH_END();
	return true;
}

static bool php_vpn_build_headers(php_vpn_request *req)
{
	HashTable seen;
	bool ok = true;

	zend_hash_init(&seen, 8, NULL, NULL, 0);
	if (req->request_headers) {
		ok = php_vpn_collect_headers(req, req->request_headers, &seen, false, true);
	}
	if (ok && req->default_headers) {
		ok = php_vpn_collect_headers(req, req->default_headers, &seen, true, false);
	}
	zend_hash_destroy(&seen);
	req->spec.headers = req->headers;
	req->spec.headers_len = req->headers_len;
	return ok;
}

static void php_vpn_settings(vpn_settings *s)
{
	const char *dir = VPN_G(lock_dir);
	zend_long ttl = VPN_G(session_ttl);
	zend_long max = VPN_G(max_tunnels);

	s->lock_dir = php_vpn_str(dir ? dir : "", dir ? strlen(dir) : 0);
	s->session_ttl = ttl > 0 ? (double)MIN(ttl, 86400) : 120.0;
	s->max_tunnels = max > 0 ? (uint32_t)MIN(max, PHP_VPN_MAX_POOL) : 4;
}
/* }}} */

/* Wraps a loaded profile in a new VPN object. Takes ownership of `profile`. */
static void php_vpn_new_object(zval *return_value, vpn_profile *profile, HashTable *options)
{
	php_vpn_object *o;

	if (options && zend_hash_num_elements(options)) {
		/* Validate now so mistakes surface where the profile is created. */
		php_vpn_request probe;
		bool ok;

		php_vpn_request_init(&probe);
		ok = php_vpn_apply_options(&probe, options, false) && php_vpn_build_headers(&probe);
		php_vpn_request_dtor(&probe);
		if (!ok) {
			vpn_profile_free(profile);
			return;
		}
	}
	object_init_ex(return_value, php_vpn_ce);
	o = php_vpn_fetch(Z_OBJ_P(return_value));
	o->profile = profile;
	if (options && zend_hash_num_elements(options)) {
		ZVAL_ARR(&o->defaults, zend_array_dup(options));
	}
}

#define PHP_VPN_SELF(o) \
	php_vpn_object *o = php_vpn_fetch(Z_OBJ_P(ZEND_THIS)); \
	if (!o->profile) { \
		zend_throw_error(NULL, "VPN object is not initialised"); \
		RETURN_THROWS(); \
	}

/* {{{ VPN */
PHP_METHOD(VPN, __construct)
{
	ZEND_PARSE_PARAMETERS_NONE();
}

PHP_METHOD(VPN, wireguard)
{
	char *path;
	size_t path_len;
	HashTable *options = NULL;
	vpn_profile *profile;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_PATH(path, path_len)
		Z_PARAM_OPTIONAL
		Z_PARAM_ARRAY_HT(options)
	ZEND_PARSE_PARAMETERS_END();

	profile = php_vpn_load_file(path, path_len);
	if (!profile) {
		RETURN_THROWS();
	}
	php_vpn_new_object(return_value, profile, options);
}

PHP_METHOD(VPN, wireguardFromString)
{
	zend_string *config;
	HashTable *options = NULL;
	vpn_profile *profile;
	vpn_error err;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STR(config)
		Z_PARAM_OPTIONAL
		Z_PARAM_ARRAY_HT(options)
	ZEND_PARSE_PARAMETERS_END();

	profile = vpn_profile_from_string(php_vpn_str(ZSTR_VAL(config), ZSTR_LEN(config)), &err);
	if (!profile) {
		php_vpn_throw_error(&err);
		RETURN_THROWS();
	}
	php_vpn_new_object(return_value, profile, options);
}

PHP_METHOD(VPN, pool)
{
	HashTable *profiles;
	HashTable *options = NULL;
	uint32_t n, i = 0, k;
	const vpn_profile **members;
	vpn_profile **owned;
	vpn_profile *pool = NULL;
	vpn_error err;
	zval *entry;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_ARRAY_HT(profiles)
		Z_PARAM_OPTIONAL
		Z_PARAM_ARRAY_HT(options)
	ZEND_PARSE_PARAMETERS_END();

	n = zend_hash_num_elements(profiles);
	if (n == 0 || n > PHP_VPN_MAX_POOL) {
		php_vpn_throw(VPN_E_CONFIG, "a pool needs between 1 and %d profiles", PHP_VPN_MAX_POOL);
		RETURN_THROWS();
	}
	members = safe_emalloc(n, sizeof(*members), 0);
	owned = ecalloc(n, sizeof(*owned));

	ZEND_HASH_FOREACH_VAL(profiles, entry) {
		ZVAL_DEREF(entry);
		if (Z_TYPE_P(entry) == IS_OBJECT && instanceof_function(Z_OBJCE_P(entry), php_vpn_ce)) {
			php_vpn_object *o = php_vpn_fetch(Z_OBJ_P(entry));
			if (!o->profile) {
				zend_throw_error(NULL, "VPN object is not initialised");
				goto done;
			}
			members[i] = o->profile;
		} else if (Z_TYPE_P(entry) == IS_STRING) {
			owned[i] = php_vpn_load_file(Z_STRVAL_P(entry), Z_STRLEN_P(entry));
			if (!owned[i]) {
				goto done;
			}
			members[i] = owned[i];
		} else {
			php_vpn_throw(VPN_E_CONFIG, "pool members must be VPN objects or profile paths, %s given", zend_zval_type_name(entry));
			goto done;
		}
		i++;
	} ZEND_HASH_FOREACH_END();

	pool = vpn_profile_pool(members, n, &err);
	if (!pool) {
		php_vpn_throw_error(&err);
	}

done:
	for (k = 0; k < n; k++) {
		if (owned[k]) {
			vpn_profile_free(owned[k]);
		}
	}
	efree(owned);
	efree(members);
	if (!pool) {
		RETURN_THROWS();
	}
	php_vpn_new_object(return_value, pool, options);
}

PHP_METHOD(VPN, request)
{
	zend_string *method, *url;
	HashTable *options = NULL;
	php_vpn_request req;
	vpn_settings settings;
	vpn_response *resp;
	vpn_error err;
	php_vpn_response_object *r;
	vpn_str s;
	size_t i, count;

	ZEND_PARSE_PARAMETERS_START(2, 3)
		Z_PARAM_STR(method)
		Z_PARAM_STR(url)
		Z_PARAM_OPTIONAL
		Z_PARAM_ARRAY_HT(options)
	ZEND_PARSE_PARAMETERS_END();

	PHP_VPN_SELF(self);

	php_vpn_request_init(&req);
	if (Z_TYPE(self->defaults) == IS_ARRAY && !php_vpn_apply_options(&req, Z_ARRVAL(self->defaults), false)) {
		goto cleanup;
	}
	if (options && !php_vpn_apply_options(&req, options, true)) {
		goto cleanup;
	}
	if (!php_vpn_build_headers(&req)) {
		goto cleanup;
	}
	req.spec.method = php_vpn_str(ZSTR_VAL(method), ZSTR_LEN(method));
	req.spec.url = php_vpn_str(ZSTR_VAL(url), ZSTR_LEN(url));
	php_vpn_settings(&settings);

	resp = vpn_request(self->profile, &req.spec, &settings, &err);
	if (!resp) {
		php_vpn_throw_error(&err);
		goto cleanup;
	}

	object_init_ex(return_value, php_vpn_response_ce);
	r = php_vpn_response_fetch(Z_OBJ_P(return_value));
	r->status = vpn_response_status(resp);
	r->redirects = vpn_response_redirects(resp);
	s = vpn_response_body(resp);
	r->body = s.len ? zend_string_init((const char *)s.ptr, s.len, 0) : ZSTR_EMPTY_ALLOC();
	s = vpn_response_url(resp);
	r->url = zend_string_init(s.len ? (const char *)s.ptr : "", s.len, 0);
	s = vpn_response_remote_ip(resp);
	r->remote = zend_string_init(s.len ? (const char *)s.ptr : "", s.len, 0);

	count = vpn_response_header_count(resp);
	for (i = 0; i < count; i++) {
		vpn_str name, value;
		zval *list, tmp;

		if (vpn_response_header(resp, i, &name, &value) != 0) {
			break;
		}
		list = zend_hash_str_find(Z_ARRVAL(r->headers), (const char *)name.ptr, name.len);
		if (!list) {
			array_init(&tmp);
			list = zend_hash_str_add(Z_ARRVAL(r->headers), (const char *)name.ptr, name.len, &tmp);
		}
		add_next_index_stringl(list, value.len ? (const char *)value.ptr : "", value.len);
	}
	vpn_response_free(resp);

cleanup:
	php_vpn_request_dtor(&req);
}

PHP_METHOD(VPN, info)
{
	char *json;

	ZEND_PARSE_PARAMETERS_NONE();
	PHP_VPN_SELF(self);

	json = vpn_profile_info_json(self->profile);
	if (!json) {
		php_vpn_throw(VPN_E_INTERNAL, "cannot describe the profile");
		RETURN_THROWS();
	}
	php_json_decode_ex(return_value, json, strlen(json), PHP_JSON_OBJECT_AS_ARRAY, 8);
	vpn_string_free(json);
	if (vpn_profile_member_count(self->profile) == 1 && Z_TYPE_P(return_value) == IS_ARRAY) {
		/* A single profile is described directly, not as a one-element list. */
		zval *first = zend_hash_index_find(Z_ARRVAL_P(return_value), 0);
		if (first) {
			zval copy;
			ZVAL_COPY(&copy, first);
			zval_ptr_dtor(return_value);
			ZVAL_COPY_VALUE(return_value, &copy);
		}
	}
}

PHP_METHOD(VPN, close)
{
	ZEND_PARSE_PARAMETERS_NONE();
	PHP_VPN_SELF(self);
	vpn_profile_close(self->profile);
}
/* }}} */

/* {{{ VPN\Response */
#define PHP_VPN_RESPONSE(r) \
	php_vpn_response_object *r = php_vpn_response_fetch(Z_OBJ_P(ZEND_THIS)); \
	if (!r->body) { \
		zend_throw_error(NULL, "VPN\\Response object is not initialised"); \
		RETURN_THROWS(); \
	}

PHP_METHOD(VPN_Response, __construct)
{
	ZEND_PARSE_PARAMETERS_NONE();
}

PHP_METHOD(VPN_Response, status)
{
	ZEND_PARSE_PARAMETERS_NONE();
	PHP_VPN_RESPONSE(r);
	RETURN_LONG(r->status);
}

PHP_METHOD(VPN_Response, headers)
{
	ZEND_PARSE_PARAMETERS_NONE();
	PHP_VPN_RESPONSE(r);
	RETURN_COPY(&r->headers);
}

PHP_METHOD(VPN_Response, header)
{
	zend_string *name, *lower;
	zval *list, *item;
	smart_str out = {0};
	bool first = true;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(name)
	ZEND_PARSE_PARAMETERS_END();
	PHP_VPN_RESPONSE(r);

	lower = zend_string_tolower(name);
	list = zend_hash_find(Z_ARRVAL(r->headers), lower);
	zend_string_release(lower);
	if (!list) {
		RETURN_NULL();
	}
	ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(list), item) {
		if (!first) {
			smart_str_appendl(&out, ", ", 2);
		}
		smart_str_append(&out, Z_STR_P(item));
		first = false;
	} ZEND_HASH_FOREACH_END();
	RETURN_STR(smart_str_extract(&out));
}

PHP_METHOD(VPN_Response, body)
{
	ZEND_PARSE_PARAMETERS_NONE();
	PHP_VPN_RESPONSE(r);
	RETURN_STR_COPY(r->body);
}

PHP_METHOD(VPN_Response, effectiveUrl)
{
	ZEND_PARSE_PARAMETERS_NONE();
	PHP_VPN_RESPONSE(r);
	RETURN_STR_COPY(r->url);
}

PHP_METHOD(VPN_Response, redirectCount)
{
	ZEND_PARSE_PARAMETERS_NONE();
	PHP_VPN_RESPONSE(r);
	RETURN_LONG(r->redirects);
}

PHP_METHOD(VPN_Response, remoteAddress)
{
	ZEND_PARSE_PARAMETERS_NONE();
	PHP_VPN_RESPONSE(r);
	RETURN_STR_COPY(r->remote);
}
/* }}} */

static void php_vpn_not_serializable(zend_class_entry *ce)
{
#if PHP_VERSION_ID >= 80100
	ce->ce_flags |= ZEND_ACC_NOT_SERIALIZABLE;
#else
	ce->serialize = zend_class_serialize_deny;
	ce->unserialize = zend_class_unserialize_deny;
#endif
}

static PHP_GINIT_FUNCTION(vpn)
{
#if defined(COMPILE_DL_VPN) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	memset(vpn_globals, 0, sizeof(*vpn_globals));
}

static PHP_MINIT_FUNCTION(vpn)
{
	zend_class_entry *base;

	/* Registration only: tunnels are created lazily in each worker process,
	 * after PHP-FPM / Apache have forked. */
	REGISTER_INI_ENTRIES();

	php_vpn_ce = register_class_VPN();
	php_vpn_ce->create_object = php_vpn_create;
	php_vpn_not_serializable(php_vpn_ce);
	memcpy(&php_vpn_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	php_vpn_handlers.offset = offsetof(php_vpn_object, std);
	php_vpn_handlers.free_obj = php_vpn_free;
	php_vpn_handlers.clone_obj = NULL;

	php_vpn_response_ce = register_class_VPN_Response();
	php_vpn_response_ce->create_object = php_vpn_response_create;
	php_vpn_not_serializable(php_vpn_response_ce);
	memcpy(&php_vpn_response_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	php_vpn_response_handlers.offset = offsetof(php_vpn_response_object, std);
	php_vpn_response_handlers.free_obj = php_vpn_response_free;
	php_vpn_response_handlers.clone_obj = NULL;
	php_vpn_response_handlers.get_debug_info = php_vpn_response_debug_info;

	base = register_class_VPN_Exception(spl_ce_RuntimeException);
	php_vpn_exception_ce[VPN_E_INTERNAL] = base;
	php_vpn_exception_ce[VPN_E_CONFIG] = register_class_VPN_ConfigException(base);
	php_vpn_exception_ce[VPN_E_TUNNEL] = register_class_VPN_TunnelException(base);
	php_vpn_exception_ce[VPN_E_DNS] = register_class_VPN_DnsException(base);
	php_vpn_exception_ce[VPN_E_CONNECT] = register_class_VPN_ConnectException(base);
	php_vpn_exception_ce[VPN_E_TLS] = register_class_VPN_TlsException(base);
	php_vpn_exception_ce[VPN_E_TIMEOUT] = register_class_VPN_TimeoutException(base);
	php_vpn_exception_ce[VPN_E_PROTOCOL] = register_class_VPN_ProtocolException(base);
	php_vpn_exception_ce[VPN_E_POLICY] = register_class_VPN_PolicyException(base);
	php_vpn_exception_ce[VPN_E_LIMIT] = register_class_VPN_LimitException(base);
	php_vpn_exception_ce[VPN_E_LOCK_TIMEOUT] = register_class_VPN_LockTimeoutException(base);

	return SUCCESS;
}

static PHP_MSHUTDOWN_FUNCTION(vpn)
{
	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}

static PHP_MINFO_FUNCTION(vpn)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "php-vpn support", "enabled");
	php_info_print_table_row(2, "Extension version", PHP_VPN_VERSION);
	php_info_print_table_row(2, "Core version", vpn_version());
	php_info_print_table_row(2, "WireGuard", "boringtun (userspace, no TUN device or root needed)");
	php_info_print_table_row(2, "TCP/IP stack", "smoltcp");
	php_info_print_table_row(2, "TLS", "rustls (bundled Mozilla root certificates)");
	php_info_print_table_end();

	DISPLAY_INI_ENTRIES();
}

static const zend_module_dep vpn_deps[] = {
	ZEND_MOD_REQUIRED("json")
	ZEND_MOD_REQUIRED("spl")
	ZEND_MOD_END
};

zend_module_entry vpn_module_entry = {
	STANDARD_MODULE_HEADER_EX,
	NULL,
	vpn_deps,
	"vpn",
	NULL,
	PHP_MINIT(vpn),
	PHP_MSHUTDOWN(vpn),
	NULL,
	NULL,
	PHP_MINFO(vpn),
	PHP_VPN_VERSION,
	PHP_MODULE_GLOBALS(vpn),
	PHP_GINIT(vpn),
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};

#ifdef COMPILE_DL_VPN
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(vpn)
#endif
