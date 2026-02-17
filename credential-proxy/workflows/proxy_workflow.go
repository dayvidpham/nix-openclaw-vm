package workflows

import (
	"strings"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/dayvidpham/nix-openclaw-vm/credential-proxy/audit"
)

// ProxyStatus represents the terminal state of a proxy workflow execution.
type ProxyStatus string

const (
	StatusInProgress ProxyStatus = "in_progress"
	StatusSuccess    ProxyStatus = "success"
	StatusDenied     ProxyStatus = "denied"
	StatusError      ProxyStatus = "error"
)

// ProxyWorkflowInput is the serializable input to the proxy request workflow.
// It intentionally contains only hashes/metadata — never real secrets.
type ProxyWorkflowInput struct {
	AgentID           string   `json:"agent_id"`
	RequestID         string   `json:"request_id"`
	TargetDomain      string   `json:"target_domain"`
	Method            string   `json:"method"`
	Path              string   `json:"path"`
	PlaceholderHashes []string `json:"placeholder_hashes"`
}

// ProxyWorkflowOutput is the workflow result recorded in Temporal history.
type ProxyWorkflowOutput struct {
	Status           ProxyStatus `json:"status"`
	LatencyMs        int64       `json:"latency_ms"`
	BytesTransferred int64       `json:"bytes_transferred"`
}

// ProxyRequestWorkflow orchestrates a single proxied request:
//
//  1. ValidateAndResolve — confirms authorization, resolves placeholder hashes
//     to vault paths (no secrets in history).
//  2. FetchAndForward — sealed activity that fetches credentials from vault,
//     injects them, forwards the request, scrubs the response.
func ProxyRequestWorkflow(ctx workflow.Context, input ProxyWorkflowInput) (*ProxyWorkflowOutput, error) {
	start := workflow.Now(ctx)

	// Upsert search attributes for observability.
	credRefHash := strings.Join(input.PlaceholderHashes, ",")
	sa := audit.NewSearchAttributes(input.AgentID, input.TargetDomain, credRefHash, string(StatusInProgress))
	if err := workflow.UpsertTypedSearchAttributes(ctx, sa.ToSearchAttributeUpdates()...); err != nil {
		return nil, err
	}

	// Activity options: short timeout for validate, longer for fetch+forward.
	validateCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts: 2,
		},
	})

	// Step 1: Validate and resolve placeholders to vault paths.
	var resolveOutput ValidateAndResolveOutput
	err := workflow.ExecuteActivity(validateCtx, (*Activities).ValidateAndResolve, ValidateAndResolveInput{
		AgentID:           input.AgentID,
		TargetDomain:      input.TargetDomain,
		PlaceholderHashes: input.PlaceholderHashes,
	}).Get(ctx, &resolveOutput)
	if err != nil {
		return finalize(ctx, start, StatusDenied, 0, err)
	}

	// Step 2: Fetch credentials, inject, forward, scrub — sealed activity.
	fetchCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts: 2,
		},
	})

	var forwardOutput FetchAndForwardOutput
	err = workflow.ExecuteActivity(fetchCtx, (*Activities).FetchAndForward, FetchAndForwardInput{
		RequestID:      input.RequestID,
		TargetDomain:   input.TargetDomain,
		Method:         input.Method,
		Path:           input.Path,
		CredentialPaths: resolveOutput.CredentialPaths,
	}).Get(ctx, &forwardOutput)
	if err != nil {
		return finalize(ctx, start, StatusError, 0, err)
	}

	return finalize(ctx, start, StatusSuccess, forwardOutput.BytesTransferred, nil)
}

// finalize upserts the terminal search attribute status and returns the output.
func finalize(ctx workflow.Context, start time.Time, status ProxyStatus, bytesTransferred int64, workflowErr error) (*ProxyWorkflowOutput, error) {
	latencyMs := workflow.Now(ctx).Sub(start).Milliseconds()

	// Best-effort status upsert — don't mask the original error.
	sa := audit.SearchAttributes{Status: string(status)}
	_ = workflow.UpsertTypedSearchAttributes(ctx, sa.ToSearchAttributeUpdates()...)

	if workflowErr != nil {
		return &ProxyWorkflowOutput{
			Status:    status,
			LatencyMs: latencyMs,
		}, workflowErr
	}

	return &ProxyWorkflowOutput{
		Status:           status,
		LatencyMs:        latencyMs,
		BytesTransferred: bytesTransferred,
	}, nil
}
