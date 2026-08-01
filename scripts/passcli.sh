# shellcheck shell=bash
#
# Resolve pass://vault/item/field references through the Proton Pass CLI.
#
# The shell half of secman_visual_check/secrets.py, for the operator scripts in
# this repository. Source it and pass any variable that may hold a credential
# through secman_resolve_var; a value that is not a reference is left alone, so
# nothing changes for anyone who does not use Proton Pass.
#
#   source scripts/passcli.sh
#   secman_resolve_var DB_PASSWORD
#
# Two properties match the Python side and are worth keeping:
#
#   * The secret never reaches a command line. Only the reference is passed to
#     pass-cli, and the value comes back through a command substitution — never
#     as an argument another process can read out of /proc.
#   * A reference that cannot be resolved is a hard error. Silently passing
#     "pass://Infra/DB/password" through as a password produces a baffling
#     access-denied three steps later.
#
# Environment:
#   SECMAN_PASS_CLI          pass-cli binary to invoke (default: pass-cli)
#   SECMAN_PASS_CLI_TIMEOUT  seconds to wait for one call (default: 30)

secman_is_secret_ref() {
  [[ "${1:-}" == pass://* ]]
}

_secman_urldecode() {
  local value="${1//+/ }"
  printf '%b' "${value//%/\\x}"
}

# secman_resolve_secret REFERENCE [LABEL] -> prints the secret on stdout
secman_resolve_secret() {
  local ref="$1" label="${2:-value}"
  local timeout_s="${SECMAN_PASS_CLI_TIMEOUT:-30}"
  local cli="${SECMAN_PASS_CLI:-pass-cli}"

  local body="${ref#pass://}"
  if [[ "$body" != */* ]]; then
    echo "error: $label: $ref is missing an item; expected pass://vault/item/field" >&2
    return 1
  fi
  local vault rest item field
  vault="$(_secman_urldecode "${body%%/*}")"
  rest="${body#*/}"
  item="$(_secman_urldecode "${rest%%/*}")"
  if [[ "$rest" == */* ]]; then
    field="$(_secman_urldecode "${rest#*/}")"
  else
    field="password"
  fi
  if [[ -z "$vault" || -z "$item" || -z "$field" ]]; then
    echo "error: $label: $ref is missing a vault, item or field" >&2
    return 1
  fi

  if ! command -v "$cli" >/dev/null 2>&1; then
    echo "error: $label: '$cli' not found. Install the Proton Pass CLI" \
         "(https://protonpass.github.io/pass-cli/) or set \$SECMAN_PASS_CLI" >&2
    return 1
  fi

  # pass-cli's flags have moved between releases, so try each known spelling.
  # `timeout` is not on every host; without it the call simply has no deadline.
  local runner=("$cli")
  if command -v timeout >/dev/null 2>&1; then
    runner=(timeout "$timeout_s" "$cli")
  fi

  local value
  if value="$("${runner[@]}" item view --vault-name "$vault" --item-title "$item" \
                --field "$field" 2>/dev/null)" && [[ -n "$value" ]]; then
    printf '%s' "$value"
    return 0
  fi
  if value="$("${runner[@]}" item view --vault-name "$vault" --item-name "$item" \
                --field "$field" 2>/dev/null)" && [[ -n "$value" ]]; then
    printf '%s' "$value"
    return 0
  fi
  if value="$("${runner[@]}" read "$ref" 2>/dev/null)" && [[ -n "$value" ]]; then
    printf '%s' "$value"
    return 0
  fi

  echo "error: $label: $cli could not resolve $ref." \
       "An unlocked session is needed — try 'pass-cli login' first" >&2
  return 1
}

# secman_resolve_var NAME — replaces $NAME in place when it holds a reference.
secman_resolve_var() {
  local name="$1"
  local value="${!name:-}"
  secman_is_secret_ref "$value" || return 0
  local resolved
  resolved="$(secman_resolve_secret "$value" "\$$name")" || return 1
  printf -v "$name" '%s' "$resolved"
}
