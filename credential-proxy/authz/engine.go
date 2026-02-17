package authz

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/rego"
)

// CredentialBinding pairs a placeholder token with its domain binding and vault path.
type CredentialBinding struct {
	Placeholder string
	BoundDomain string
	VaultPath   string
}

// AuthzRequest is the input sent to the OPA policy for evaluation.
type AuthzRequest struct {
	// Identity contains JWT claims (e.g., "roles", "sub", "realm_access").
	Identity map[string]interface{}

	// Placeholders are the opaque tokens found in the outbound request body/headers.
	Placeholders []string

	// TargetDomain is the domain the agent is trying to reach.
	TargetDomain string

	// Credentials are the resolved credential bindings for the placeholders.
	Credentials []CredentialBinding
}

// AuthzResult is the outcome of a policy evaluation.
type AuthzResult struct {
	Allowed bool
	Reason  string
}

// Evaluator is the interface for authorization policy evaluation.
type Evaluator interface {
	Evaluate(ctx context.Context, req *AuthzRequest) (*AuthzResult, error)
}

// OPAEvaluator loads Rego policies from disk and evaluates them using the embedded OPA engine.
type OPAEvaluator struct {
	allowQuery      rego.PreparedEvalQuery
	denyReasonsQuery rego.PreparedEvalQuery
}

// NewOPAEvaluator creates an evaluator by loading all .rego files from policyDir.
func NewOPAEvaluator(ctx context.Context, policyDir string) (*OPAEvaluator, error) {
	modules, err := loadRegoModules(policyDir)
	if err != nil {
		return nil, fmt.Errorf("load rego policies from %s: %w", policyDir, err)
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("no .rego files found in %s", policyDir)
	}

	// Build rego options shared by both queries.
	opts := make([]func(*rego.Rego), 0, len(modules)+1)
	for name, src := range modules {
		opts = append(opts, rego.Module(name, src))
	}

	// Prepare the allow query.
	allowOpts := append(append([]func(*rego.Rego){}, opts...), rego.Query("data.credproxy.authz.allow"))
	allowQuery, err := rego.New(allowOpts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare allow query: %w", err)
	}

	// Prepare the deny_reasons query.
	denyOpts := append(append([]func(*rego.Rego){}, opts...), rego.Query("data.credproxy.authz.deny_reasons"))
	denyReasonsQuery, err := rego.New(denyOpts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare deny_reasons query: %w", err)
	}

	return &OPAEvaluator{
		allowQuery:      allowQuery,
		denyReasonsQuery: denyReasonsQuery,
	}, nil
}

// Evaluate runs the loaded policies against the given authorization request.
func (e *OPAEvaluator) Evaluate(ctx context.Context, req *AuthzRequest) (*AuthzResult, error) {
	input := buildInput(req)

	// Evaluate allow.
	allowRS, err := e.allowQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("evaluate allow: %w", err)
	}

	allowed := extractBool(allowRS)

	if allowed {
		return &AuthzResult{Allowed: true, Reason: ""}, nil
	}

	// Not allowed — collect deny reasons.
	denyRS, err := e.denyReasonsQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("evaluate deny_reasons: %w", err)
	}

	reasons := extractStringSet(denyRS)
	return &AuthzResult{
		Allowed: false,
		Reason:  strings.Join(reasons, "; "),
	}, nil
}

// buildInput converts an AuthzRequest into the map that Rego sees as `input`.
func buildInput(req *AuthzRequest) map[string]interface{} {
	creds := make([]map[string]interface{}, len(req.Credentials))
	for i, c := range req.Credentials {
		creds[i] = map[string]interface{}{
			"placeholder":  c.Placeholder,
			"bound_domain": c.BoundDomain,
			"vault_path":   c.VaultPath,
		}
	}
	return map[string]interface{}{
		"identity":      req.Identity,
		"placeholders":  req.Placeholders,
		"target_domain": req.TargetDomain,
		"credentials":   creds,
	}
}

// extractBool pulls a boolean from the first expression of a result set.
func extractBool(rs rego.ResultSet) bool {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return false
	}
	b, ok := rs[0].Expressions[0].Value.(bool)
	return ok && b
}

// extractStringSet pulls a set of strings from the first expression of a result set.
func extractStringSet(rs rego.ResultSet) []string {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil
	}

	var out []string

	switch v := rs[0].Expressions[0].Value.(type) {
	case []interface{}:
		for _, elem := range v {
			if s, ok := elem.(string); ok {
				out = append(out, s)
			}
		}
	case map[string]interface{}:
		// OPA sometimes returns sets as maps with empty-struct values.
		for key := range v {
			out = append(out, key)
		}
	}

	return out
}

// loadRegoModules reads all .rego files from dir and returns filename→source.
func loadRegoModules(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	modules := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rego") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		modules[entry.Name()] = string(data)
	}
	return modules, nil
}
