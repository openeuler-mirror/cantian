#!/bin/bash
set -eo pipefail
shopt -s nullglob

# logging functions
connector_log() {
  local type="$1"
  shift
  # accept argument string or stdin
  local text="$*"
  if [ "$#" -eq 0 ]; then text="$(cat)"; fi
  local dt
  dt="$(date --rfc-3339=seconds)"
  printf '%s [%s] [InitConnectorPlugin]: %s\n' "$dt" "$type" "$text"
}

connector_note() {
  connector_log Note "$@"
}

connector_warn() {
  connector_log Warn "$@" >&2
}

connector_error() {
  connector_log ERROR "$@" >&2
  exit 1
}

install_cantian_lib() {
  if [ -d "/mf_connector/cantian_lib" ]; then
    connector_note "Find cantian lib"
    /mf_connector/cantian_lib/install_cantian_lib.sh
    connector_note "Installed cantian lib"
  else
    connector_warn "Cannot find cantian lib"
  fi
}

install_mf_connector_plugin() {
  if [ -d "/mf_connector/plugin" ]; then
    connector_note "Find mf_connector plugin"
    /mf_connector/plugin/install_mf_connector_plugin.sh
    connector_note "Installed mf_connector plugin"
  else
    connector_warn "Cannot find mf_connector plugin"
  fi
}

# check to see if this file is being run or sourced from another script
_is_sourced() {
  [ "${#FUNCNAME[@]}" -ge 2 ] &&
    [ "${FUNCNAME[0]}" = '_is_sourced' ] &&
    [ "${FUNCNAME[1]}" = 'source' ]
}

_main() {
  install_cantian_lib
  install_mf_connector_plugin
}

# If we are sourced from elsewhere, don't perform any further actions
if ! _is_sourced; then
  _main "$@"
fi
