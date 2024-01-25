#!/bin/bash
set -eo pipefail
shopt -s nullglob

copy_cantian_lib() {
  cp -p --remove-destination /mf_connector/cantian_lib/*.so* /usr/lib64
}

link_cantian_lib() {
  if [ -f /usr/lib64/libibverbs.so.1 ];then
    ln -s -f /usr/lib64/libibverbs.so.1 /usr/lib64/libibverbs.so
  fi
  if [ -f /usr/lib64/libibverbs.so.1.11.32.0 ];then
    ln -s -f /usr/lib64/libibverbs.so.1.11.32.0 /usr/lib64/libibverbs.so.1
  fi
  if [ -f /usr/lib64/liblz4.so.1.9.4 ];then
    ln -s -f /usr/lib64/liblz4.so.1.9.4 /usr/lib64/liblz4.so.1
  fi
  if [ -f /usr/lib64/libmxml.so ];then
    ln -s -f /usr/lib64/libmxml.so /usr/lib64/libmxml.so.1
  fi
  if [ -f libpcre2-8.so.0.11.2 ];then
    ln -s -f /usr/lib64/libpcre2-8.so.0.11.2 /usr/lib64/libpcre2-8.so.0
  fi
  if [ -f /usr/lib64/libpmem.so.1 ];then
    ln -s -f /usr/lib64/libpmem.so.1 /usr/lib64/libpmem.so
  fi
  if [ -f libpmem.so.1.0.0 ];then
    ln -s -f /usr/lib64/libpmem.so.1.0.0 /usr/lib64/libpmem.so.1
  fi
  if [ -f /usr/lib64/librdmacm.so.1 ];then
    ln -s -f /usr/lib64/librdmacm.so.1 /usr/lib64/librdmacm.so
  fi
  if [ -f /usr/lib64/librdmacm.so.1.3.32.0 ];then
    ln -s -f /usr/lib64/librdmacm.so.1.3.32.0 /usr/lib64/librdmacm.so.1
  fi
  if [ -f /usr/lib64/libuuid.so.1.3.0 ];then
    ln -s -f /usr/lib64/libuuid.so.1.3.0 /usr/lib64/libuuid.so.1
  fi
}

# check to see if this file is being run or sourced from another script
_is_sourced() {
  [ "${#FUNCNAME[@]}" -ge 2 ] &&
    [ "${FUNCNAME[0]}" = '_is_sourced' ] &&
    [ "${FUNCNAME[1]}" = 'source' ]
}

_main() {
  copy_cantian_lib
  link_cantian_lib
}

# If we are sourced from elsewhere, don't perform any further actions
if ! _is_sourced; then
  _main "$@"
fi
