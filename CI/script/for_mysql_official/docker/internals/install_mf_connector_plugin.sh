#!/bin/bash
set -eo pipefail
shopt -s nullglob

copy_mf_connector_plugin() {
  local default_plugin_dir="/usr/lib/mysql/plugin"
  if [ ! -d "${default_plugin_dir}" ]; then
    default_plugin_dir="/usr/lib64/mysql/plugin"
  fi
  cp -p --remove-destination /mf_connector/plugin/*.so* "${default_plugin_dir}"
}

# check to see if this file is being run or sourced from another script
_is_sourced() {
  [ "${#FUNCNAME[@]}" -ge 2 ] &&
    [ "${FUNCNAME[0]}" = '_is_sourced' ] &&
    [ "${FUNCNAME[1]}" = 'source' ]
}

_main() {
  copy_mf_connector_plugin
}

# If we are sourced from elsewhere, don't perform any further actions
if ! _is_sourced; then
  _main "$@"
fi
