# credproxy-auth — Authenticate to Keycloak and obtain a JWT for the credential proxy.
#
# Reads configuration from environment variables or /etc/credproxy/client.env.
# Caches the JWT to $CREDPROXY_TOKEN_FILE with mode 600.
# Prints the token to stdout on success.
#
# Required configuration (env vars or /etc/credproxy/client.env):
#   CREDPROXY_KEYCLOAK_URL    — Keycloak token endpoint
#   CREDPROXY_CLIENT_ID       — OIDC client ID
#   CREDPROXY_CLIENT_SECRET   — OIDC client secret (or set CREDPROXY_CLIENT_SECRET_FILE)

CREDPROXY_ENV_FILE="${CREDPROXY_ENV_FILE:-/etc/credproxy/client.env}"
CREDPROXY_TOKEN_FILE="${CREDPROXY_TOKEN_FILE:-${XDG_RUNTIME_DIR:-/tmp}/credproxy-jwt}"

# Load configuration from env file if it exists and vars are not already set
if [ -f "$CREDPROXY_ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$CREDPROXY_ENV_FILE"
fi

# Read client secret from file if not set directly
if [ -z "${CREDPROXY_CLIENT_SECRET:-}" ] && [ -n "${CREDPROXY_CLIENT_SECRET_FILE:-}" ]; then
  CREDPROXY_CLIENT_SECRET=$(cat "$CREDPROXY_CLIENT_SECRET_FILE")
fi

# Validate required configuration
if [ -z "${CREDPROXY_KEYCLOAK_URL:-}" ]; then
  echo "error: CREDPROXY_KEYCLOAK_URL is not set" >&2
  echo "Set it in the environment or in $CREDPROXY_ENV_FILE" >&2
  exit 1
fi

if [ -z "${CREDPROXY_CLIENT_ID:-}" ]; then
  echo "error: CREDPROXY_CLIENT_ID is not set" >&2
  echo "Set it in the environment or in $CREDPROXY_ENV_FILE" >&2
  exit 1
fi

if [ -z "${CREDPROXY_CLIENT_SECRET:-}" ]; then
  echo "error: CREDPROXY_CLIENT_SECRET is not set" >&2
  echo "Set it in the environment, in $CREDPROXY_ENV_FILE, or via CREDPROXY_CLIENT_SECRET_FILE" >&2
  exit 1
fi

# Request token using client_credentials grant.
# Capture stderr separately so curl error messages don't leak into the response.
curl_stderr=$(mktemp)
trap 'rm -f "$curl_stderr"' EXIT
response=$(curl --silent --show-error --fail \
  --request POST \
  --header "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=${CREDPROXY_CLIENT_ID}" \
  --data-urlencode "client_secret=${CREDPROXY_CLIENT_SECRET}" \
  "$CREDPROXY_KEYCLOAK_URL" 2>"$curl_stderr") || {
  echo "error: failed to obtain token from Keycloak" >&2
  cat "$curl_stderr" >&2
  exit 1
}

# Extract access_token from JSON response using jq
if ! token=$(printf '%s' "$response" | jq -r '.access_token // empty'); then
  echo "error: failed to parse Keycloak response (check endpoint and credentials)" >&2
  exit 1
fi

if [ -z "$token" ]; then
  echo "error: no access_token in Keycloak response (check endpoint and credentials)" >&2
  exit 1
fi

# Cache token with restrictive permissions
(
  umask 0177
  printf '%s' "$token" > "$CREDPROXY_TOKEN_FILE"
)

printf '%s\n' "$token"
