# credproxy-request — Make HTTP requests through the credential proxy with JWT auth.
#
# Usage:
#   credproxy-request METHOD URL [CURL_OPTIONS...]
#
# Examples:
#   credproxy-request GET https://api.anthropic.com/v1/messages
#   credproxy-request POST https://api.anthropic.com/v1/messages \
#     -H "Content-Type: application/json" -d '{"model":"claude-3"}'
#
# The script adds Proxy-Authorization: Bearer <jwt> to route authenticated
# requests through the credential proxy's MITM pipeline.
#
# Token resolution order:
#   1. $CREDPROXY_TOKEN environment variable
#   2. Cached token file (default: ${XDG_RUNTIME_DIR:-/tmp}/credproxy-jwt)

CREDPROXY_TOKEN_FILE="${CREDPROXY_TOKEN_FILE:-${XDG_RUNTIME_DIR:-/tmp}/credproxy-jwt}"

usage() {
  echo "Usage: credproxy-request METHOD URL [CURL_OPTIONS...]" >&2
  echo "" >&2
  echo "Make HTTP requests through the credential proxy." >&2
  echo "" >&2
  echo "Arguments:" >&2
  echo "  METHOD        HTTP method (GET, POST, PUT, DELETE, ...)" >&2
  echo "  URL           Target URL" >&2
  echo "  CURL_OPTIONS  Additional arguments passed directly to curl" >&2
  echo "" >&2
  echo "Environment:" >&2
  echo "  CREDPROXY_TOKEN       JWT token (overrides cached file)" >&2
  echo "  CREDPROXY_TOKEN_FILE  Path to cached JWT (default: \${XDG_RUNTIME_DIR:-/tmp}/credproxy-jwt)" >&2
  echo "  HTTPS_PROXY           Proxy address (set by guest module)" >&2
}

if [ $# -lt 2 ]; then
  usage
  exit 1
fi

method="$1"
url="$2"
shift 2

# Resolve JWT token
token="${CREDPROXY_TOKEN:-}"

if [ -z "$token" ] && [ -f "$CREDPROXY_TOKEN_FILE" ]; then
  token=$(cat "$CREDPROXY_TOKEN_FILE")
fi

if [ -z "$token" ]; then
  echo "error: no credential proxy JWT available" >&2
  echo "" >&2
  echo "Authenticate first by running:" >&2
  echo "  credproxy-auth" >&2
  echo "" >&2
  echo "Or set CREDPROXY_TOKEN in your environment." >&2
  exit 1
fi

# Execute the request through the proxy with JWT authorization.
# HTTPS_PROXY is already set by the guest NixOS module; curl respects it.
# Proxy-Authorization carries the JWT for the proxy's OIDC validation.
exec curl \
  --silent --show-error \
  --request "$method" \
  --proxy-header "Proxy-Authorization: Bearer ${token}" \
  "$@" \
  "$url"
