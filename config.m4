dnl config.m4 for php-vpn

PHP_ARG_ENABLE([vpn],
  [whether to enable php-vpn],
  [AS_HELP_STRING([--enable-vpn],
    [Enable php-vpn (per-request userspace WireGuard egress)])],
  [no])

PHP_ARG_WITH([vpn-core],
  [prebuilt Rust core],
  [AS_HELP_STRING([[--with-vpn-core[=PATH]]],
    [Path to a prebuilt libvpn_ffi.a (default: build it with cargo)])],
  [no],
  [no])

dnl A plain feature flag (not PHP_ARG_ENABLE, which phpize turns into "yes").
AC_ARG_ENABLE([vpn-static-libgcc],
  [AS_HELP_STRING([--enable-vpn-static-libgcc],
    [Link libgcc_eh statically instead of needing libgcc_s.so.1 at run time (musl/Alpine images such as php:8.0-cli-alpine do not ship libgcc)])],
  [vpn_static_libgcc="$enableval"],
  [vpn_static_libgcc=no])

if test "$PHP_VPN" != "no"; then
  vpn_srcdir="$abs_srcdir"
  test -z "$vpn_srcdir" && vpn_srcdir="`pwd`"

  if test "$PHP_VPN_CORE" != "no" && test "$PHP_VPN_CORE" != "yes"; then
    VPN_CORE_LIB="$PHP_VPN_CORE"
  else
    AC_PATH_PROG([CARGO], [cargo], [no])
    if test "$CARGO" = "no"; then
      AC_MSG_ERROR([cargo was not found: install Rust (https://rustup.rs) or pass --with-vpn-core=/path/to/libvpn_ffi.a])
    fi
    AC_MSG_NOTICE([building the Rust core with $CARGO])
    (cd "$vpn_srcdir/core" && "$CARGO" build --release --locked -p vpn-ffi) || AC_MSG_ERROR([cargo build of the Rust core failed])
    VPN_CORE_LIB="$vpn_srcdir/core/target/release/libvpn_ffi.a"
  fi

  if test ! -f "$VPN_CORE_LIB"; then
    AC_MSG_ERROR([Rust core library $VPN_CORE_LIB not found])
  fi
  AC_MSG_RESULT([using Rust core $VPN_CORE_LIB])

  PHP_ADD_INCLUDE([$vpn_srcdir/include])
  dnl Link the core statically and export only get_module, so nothing from
  dnl Rust (or its dependencies) can clash with other extensions.
  if test "$vpn_static_libgcc" = "yes"; then
    VPN_LIBGCC="-Wl,-Bstatic -lgcc_eh -lgcc -Wl,-Bdynamic"
  else
    VPN_LIBGCC="-lgcc_s"
  fi
  VPN_SHARED_LIBADD="$VPN_CORE_LIB $VPN_LIBGCC -lutil -lrt -lpthread -lm -ldl -Wl,--version-script=$vpn_srcdir/php-vpn.map -Wl,--exclude-libs,ALL"
  PHP_SUBST([VPN_SHARED_LIBADD])

  PHP_NEW_EXTENSION([vpn], [php_vpn.c], [$ext_shared],, [-DZEND_ENABLE_STATIC_TSRMLS_CACHE=1])
  PHP_ADD_EXTENSION_DEP([vpn], [json])
  PHP_ADD_EXTENSION_DEP([vpn], [spl])
fi
