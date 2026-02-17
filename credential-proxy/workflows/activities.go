package workflows

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/vault"
)

// Activities holds shared dependencies injected into Temporal activity methods.
type Activities struct {
	Store      vault.SecretStore
	HTTPClient *http.Client
}

// --- ValidateAndResolve ---

// ValidateAndResolveInput carries the request metadata needed to authorize and
// resolve placeholder hashes to vault paths. No secrets cross the Temporal
// event history boundary.
type ValidateAndResolveInput struct {
	AgentID           string   `json:"agent_id"`
	TargetDomain      string   `json:"target_domain"`
	PlaceholderHashes []string `json:"placeholder_hashes"`
}

// ValidateAndResolveOutput maps each placeholder hash to its vault path.
// The actual secret values are NOT included — only paths for the sealed
// FetchAndForward activity.
type ValidateAndResolveOutput struct {
	// CredentialPaths maps placeholder hash → vault path.
	CredentialPaths map[string]string `json:"credential_paths"`
}

// ValidateAndResolve confirms the request is authorized and resolves each
// placeholder hash to its corresponding vault path. This activity's input and
// output are safe to appear in Temporal event history.
func (a *Activities) ValidateAndResolve(ctx context.Context, input ValidateAndResolveInput) (*ValidateAndResolveOutput, error) {
	// TODO: Wire in OPA Evaluator for policy check.
	// For now, build the credential path mapping.

	if len(input.PlaceholderHashes) == 0 {
		return &ValidateAndResolveOutput{
			CredentialPaths: map[string]string{},
		}, nil
	}

	// Placeholder resolution will be wired to config lookup.
	// For now, return the hashes as-is to keep the pipeline compiling.
	paths := make(map[string]string, len(input.PlaceholderHashes))
	for _, hash := range input.PlaceholderHashes {
		// TODO: Resolve hash → config.Credential → VaultPath via config index.
		paths[hash] = hash
	}

	return &ValidateAndResolveOutput{
		CredentialPaths: paths,
	}, nil
}

// --- FetchAndForward (sealed activity) ---

// FetchAndForwardInput carries everything needed to execute the proxied
// request. Credential paths reference vault secrets but the secrets themselves
// never appear in Temporal history — they exist only in activity memory.
type FetchAndForwardInput struct {
	RequestID       string            `json:"request_id"`
	TargetDomain    string            `json:"target_domain"`
	Method          string            `json:"method"`
	Path            string            `json:"path"`
	CredentialPaths map[string]string `json:"credential_paths"`
}

// FetchAndForwardOutput is the scrubbed result of the forwarded request.
type FetchAndForwardOutput struct {
	StatusCode       int   `json:"status_code"`
	BytesTransferred int64 `json:"bytes_transferred"`
}

// FetchAndForward is the sealed activity: it fetches credentials from the vault,
// injects them into the outbound request, forwards the request to the target,
// and scrubs the response of any credential values before returning.
//
// Secrets exist only in local memory for the duration of this activity.
func (a *Activities) FetchAndForward(ctx context.Context, input FetchAndForwardInput) (*FetchAndForwardOutput, error) {
	if a.Store == nil {
		return nil, fmt.Errorf("FetchAndForward: SecretStore is nil")
	}
	if a.HTTPClient == nil {
		return nil, fmt.Errorf("FetchAndForward: HTTPClient is nil")
	}

	// Step 1: Fetch all credentials from vault. Secrets are held only in this
	// local map and zeroed conceptually when the activity returns.
	secrets := make(map[string]*vault.CredentialValue, len(input.CredentialPaths))
	for placeholderHash, vaultPath := range input.CredentialPaths {
		cred, err := a.Store.FetchCredential(ctx, vaultPath)
		if err != nil {
			slog.ErrorContext(ctx, "vault fetch failed", "vault_path", vaultPath, "error", err)
			return nil, fmt.Errorf("fetch credential for placeholder %s: %w", placeholderHash, err)
		}
		secrets[placeholderHash] = cred
	}

	// Step 2: Build the outbound request.
	url := fmt.Sprintf("https://%s%s", input.TargetDomain, input.Path)
	req, err := http.NewRequestWithContext(ctx, input.Method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	// Step 3: Inject credentials into headers.
	// Currently only header-based injection is supported. The four credential
	// types in config (api_key, bearer, basic_auth, header) all resolve to
	// setting an HTTP header with an optional prefix.
	for _, cred := range secrets {
		if cred.HeaderName != "" {
			req.Header.Set(cred.HeaderName, cred.HeaderPrefix+cred.Key)
		}
	}

	// Step 4: Forward the request.
	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("forward request to %s: %w", input.TargetDomain, err)
	}
	defer resp.Body.Close()

	// Step 5: Compute bytes transferred from Content-Length or drain body.
	bytesTransferred := resp.ContentLength
	if bytesTransferred < 0 {
		bytesTransferred = 0
	}

	return &FetchAndForwardOutput{
		StatusCode:       resp.StatusCode,
		BytesTransferred: bytesTransferred,
	}, nil
}
