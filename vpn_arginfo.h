/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 36a9b4af1191b3f650b5bb742e98180036bef53d */

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_VPN___construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_VPN_wireguard, 0, 1, VPN, 0)
	ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_VPN_wireguardFromString, 0, 1, VPN, 0)
	ZEND_ARG_TYPE_INFO(0, config, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_VPN_pool, 0, 1, VPN, 0)
	ZEND_ARG_TYPE_INFO(0, profiles, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_VPN_request, 0, 2, VPN\\Response, 0)
	ZEND_ARG_TYPE_INFO(0, method, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, url, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_VPN_info, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_VPN_close, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_VPN_Response___construct arginfo_class_VPN___construct

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_VPN_Response_status, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_VPN_Response_headers arginfo_class_VPN_info

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_VPN_Response_header, 0, 1, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_VPN_Response_body, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_VPN_Response_effectiveUrl arginfo_class_VPN_Response_body

#define arginfo_class_VPN_Response_redirectCount arginfo_class_VPN_Response_status

#define arginfo_class_VPN_Response_remoteAddress arginfo_class_VPN_Response_body

ZEND_METHOD(VPN, __construct);
ZEND_METHOD(VPN, wireguard);
ZEND_METHOD(VPN, wireguardFromString);
ZEND_METHOD(VPN, pool);
ZEND_METHOD(VPN, request);
ZEND_METHOD(VPN, info);
ZEND_METHOD(VPN, close);
ZEND_METHOD(VPN_Response, __construct);
ZEND_METHOD(VPN_Response, status);
ZEND_METHOD(VPN_Response, headers);
ZEND_METHOD(VPN_Response, header);
ZEND_METHOD(VPN_Response, body);
ZEND_METHOD(VPN_Response, effectiveUrl);
ZEND_METHOD(VPN_Response, redirectCount);
ZEND_METHOD(VPN_Response, remoteAddress);

static const zend_function_entry class_VPN_methods[] = {
	ZEND_ME(VPN, __construct, arginfo_class_VPN___construct, ZEND_ACC_PRIVATE)
	ZEND_ME(VPN, wireguard, arginfo_class_VPN_wireguard, ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
	ZEND_ME(VPN, wireguardFromString, arginfo_class_VPN_wireguardFromString, ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
	ZEND_ME(VPN, pool, arginfo_class_VPN_pool, ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
	ZEND_ME(VPN, request, arginfo_class_VPN_request, ZEND_ACC_PUBLIC)
	ZEND_ME(VPN, info, arginfo_class_VPN_info, ZEND_ACC_PUBLIC)
	ZEND_ME(VPN, close, arginfo_class_VPN_close, ZEND_ACC_PUBLIC)
	ZEND_FE_END
};

static const zend_function_entry class_VPN_Response_methods[] = {
	ZEND_ME(VPN_Response, __construct, arginfo_class_VPN_Response___construct, ZEND_ACC_PRIVATE)
	ZEND_ME(VPN_Response, status, arginfo_class_VPN_Response_status, ZEND_ACC_PUBLIC)
	ZEND_ME(VPN_Response, headers, arginfo_class_VPN_Response_headers, ZEND_ACC_PUBLIC)
	ZEND_ME(VPN_Response, header, arginfo_class_VPN_Response_header, ZEND_ACC_PUBLIC)
	ZEND_ME(VPN_Response, body, arginfo_class_VPN_Response_body, ZEND_ACC_PUBLIC)
	ZEND_ME(VPN_Response, effectiveUrl, arginfo_class_VPN_Response_effectiveUrl, ZEND_ACC_PUBLIC)
	ZEND_ME(VPN_Response, redirectCount, arginfo_class_VPN_Response_redirectCount, ZEND_ACC_PUBLIC)
	ZEND_ME(VPN_Response, remoteAddress, arginfo_class_VPN_Response_remoteAddress, ZEND_ACC_PUBLIC)
	ZEND_FE_END
};

static zend_class_entry *register_class_VPN(void)
{
	zend_class_entry ce, *class_entry;

	INIT_CLASS_ENTRY(ce, "VPN", class_VPN_methods);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, NULL, ZEND_ACC_FINAL|ZEND_ACC_NO_DYNAMIC_PROPERTIES);
#else
	class_entry = zend_register_internal_class_ex(&ce, NULL);
	class_entry->ce_flags |= ZEND_ACC_FINAL|ZEND_ACC_NO_DYNAMIC_PROPERTIES;
#endif

	zval const_VERSION_value;
	zend_string *const_VERSION_value_str = zend_string_init(PHP_VPN_VERSION, strlen(PHP_VPN_VERSION), 1);
	ZVAL_STR(&const_VERSION_value, const_VERSION_value_str);
	zend_string *const_VERSION_name = zend_string_init_interned("VERSION", sizeof("VERSION") - 1, 1);
#if (PHP_VERSION_ID >= 80300)
	zend_declare_typed_class_constant(class_entry, const_VERSION_name, &const_VERSION_value, ZEND_ACC_PUBLIC, NULL, (zend_type) ZEND_TYPE_INIT_MASK(MAY_BE_STRING));
#else
	zend_declare_class_constant_ex(class_entry, const_VERSION_name, &const_VERSION_value, ZEND_ACC_PUBLIC, NULL);
#endif
	zend_string_release(const_VERSION_name);


	zend_string *attribute_name_SensitiveParameter_func_wireguardfromstring_arg0_0 = zend_string_init_interned("SensitiveParameter", sizeof("SensitiveParameter") - 1, 1);
	zend_add_parameter_attribute(zend_hash_str_find_ptr(&class_entry->function_table, "wireguardfromstring", sizeof("wireguardfromstring") - 1), 0, attribute_name_SensitiveParameter_func_wireguardfromstring_arg0_0, 0);
	zend_string_release(attribute_name_SensitiveParameter_func_wireguardfromstring_arg0_0);

	return class_entry;
}

static zend_class_entry *register_class_VPN_Response(void)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "VPN", "Response", class_VPN_Response_methods);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, NULL, ZEND_ACC_FINAL|ZEND_ACC_NO_DYNAMIC_PROPERTIES);
#else
	class_entry = zend_register_internal_class_ex(&ce, NULL);
	class_entry->ce_flags |= ZEND_ACC_FINAL|ZEND_ACC_NO_DYNAMIC_PROPERTIES;
#endif

	return class_entry;
}

static zend_class_entry *register_class_VPN_Exception(zend_class_entry *class_entry_RuntimeException)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "VPN", "Exception", NULL);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, class_entry_RuntimeException, 0);
#else
	class_entry = zend_register_internal_class_ex(&ce, class_entry_RuntimeException);
#endif

	return class_entry;
}

static zend_class_entry *register_class_VPN_ConfigException(zend_class_entry *class_entry_VPN_Exception)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "VPN", "ConfigException", NULL);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, class_entry_VPN_Exception, 0);
#else
	class_entry = zend_register_internal_class_ex(&ce, class_entry_VPN_Exception);
#endif

	return class_entry;
}

static zend_class_entry *register_class_VPN_TunnelException(zend_class_entry *class_entry_VPN_Exception)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "VPN", "TunnelException", NULL);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, class_entry_VPN_Exception, 0);
#else
	class_entry = zend_register_internal_class_ex(&ce, class_entry_VPN_Exception);
#endif

	return class_entry;
}

static zend_class_entry *register_class_VPN_DnsException(zend_class_entry *class_entry_VPN_Exception)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "VPN", "DnsException", NULL);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, class_entry_VPN_Exception, 0);
#else
	class_entry = zend_register_internal_class_ex(&ce, class_entry_VPN_Exception);
#endif

	return class_entry;
}

static zend_class_entry *register_class_VPN_ConnectException(zend_class_entry *class_entry_VPN_Exception)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "VPN", "ConnectException", NULL);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, class_entry_VPN_Exception, 0);
#else
	class_entry = zend_register_internal_class_ex(&ce, class_entry_VPN_Exception);
#endif

	return class_entry;
}

static zend_class_entry *register_class_VPN_TlsException(zend_class_entry *class_entry_VPN_Exception)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "VPN", "TlsException", NULL);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, class_entry_VPN_Exception, 0);
#else
	class_entry = zend_register_internal_class_ex(&ce, class_entry_VPN_Exception);
#endif

	return class_entry;
}

static zend_class_entry *register_class_VPN_TimeoutException(zend_class_entry *class_entry_VPN_Exception)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "VPN", "TimeoutException", NULL);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, class_entry_VPN_Exception, 0);
#else
	class_entry = zend_register_internal_class_ex(&ce, class_entry_VPN_Exception);
#endif

	return class_entry;
}

static zend_class_entry *register_class_VPN_ProtocolException(zend_class_entry *class_entry_VPN_Exception)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "VPN", "ProtocolException", NULL);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, class_entry_VPN_Exception, 0);
#else
	class_entry = zend_register_internal_class_ex(&ce, class_entry_VPN_Exception);
#endif

	return class_entry;
}

static zend_class_entry *register_class_VPN_PolicyException(zend_class_entry *class_entry_VPN_Exception)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "VPN", "PolicyException", NULL);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, class_entry_VPN_Exception, 0);
#else
	class_entry = zend_register_internal_class_ex(&ce, class_entry_VPN_Exception);
#endif

	return class_entry;
}

static zend_class_entry *register_class_VPN_LimitException(zend_class_entry *class_entry_VPN_Exception)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "VPN", "LimitException", NULL);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, class_entry_VPN_Exception, 0);
#else
	class_entry = zend_register_internal_class_ex(&ce, class_entry_VPN_Exception);
#endif

	return class_entry;
}

static zend_class_entry *register_class_VPN_LockTimeoutException(zend_class_entry *class_entry_VPN_Exception)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "VPN", "LockTimeoutException", NULL);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, class_entry_VPN_Exception, 0);
#else
	class_entry = zend_register_internal_class_ex(&ce, class_entry_VPN_Exception);
#endif

	return class_entry;
}
