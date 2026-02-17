package credproxy.authz

import future.keywords.every
import future.keywords.contains
import future.keywords.if

default allow := false

# Allow if the identity has at least one role AND every credential is bound to the target domain.
allow if {
	has_roles
	all_credentials_bound
}

# True when the identity carries a non-empty roles list.
has_roles if {
	roles := input.identity.roles
	count(roles) > 0
}

# True when every credential's bound_domain matches the target_domain.
all_credentials_bound if {
	count(input.credentials) > 0
	every cred in input.credentials {
		cred.bound_domain == input.target_domain
	}
}

# Also allow when there are no credentials to check (pure domain allowlist request)
# but identity still needs roles.
all_credentials_bound if {
	count(input.credentials) == 0
}

# --- deny_reasons -----------------------------------------------------------
# Each rule adds a human-readable string to the set when its condition is true.

deny_reasons contains "no roles in identity" if {
	not has_roles
}

deny_reasons contains msg if {
	some cred in input.credentials
	cred.bound_domain != input.target_domain
	msg := sprintf("credential %s not bound to domain %s", [cred.placeholder, input.target_domain])
}
