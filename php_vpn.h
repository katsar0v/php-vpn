#ifndef PHP_VPN_H
#define PHP_VPN_H

extern zend_module_entry vpn_module_entry;
#define phpext_vpn_ptr &vpn_module_entry

#define PHP_VPN_VERSION "0.1.0"

ZEND_BEGIN_MODULE_GLOBALS(vpn)
	double default_timeout;
	double connect_timeout;
	zend_long max_response_size;
	zend_long max_redirects;
	char *ca_file;
	zend_bool allow_private_destinations;
	char *lock_dir;
	zend_long session_ttl;
	zend_long max_tunnels;
	char *allowed_config_dir;
	zend_bool enforce_key_permissions;
ZEND_END_MODULE_GLOBALS(vpn)

ZEND_EXTERN_MODULE_GLOBALS(vpn)
#define VPN_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(vpn, v)

#if defined(ZTS) && defined(COMPILE_DL_VPN)
ZEND_TSRMLS_CACHE_EXTERN()
#endif

#endif
