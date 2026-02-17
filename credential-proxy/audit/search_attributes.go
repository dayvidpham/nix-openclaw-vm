package audit

import (
	"go.temporal.io/sdk/temporal"
)

// Search attribute key names registered with Temporal for proxy workflow visibility.
const (
	AttrAgentID           = "CredProxyAgentID"
	AttrTargetDomain      = "CredProxyTargetDomain"
	AttrCredentialRefHash = "CredProxyCredentialRefHash"
	AttrStatus            = "CredProxyStatus"
)

// SearchAttributes holds the typed values for a single proxy workflow execution.
type SearchAttributes struct {
	AgentID           string
	TargetDomain      string
	CredentialRefHash string
	Status            string
}

// NewSearchAttributes creates a SearchAttributes with the given fields.
func NewSearchAttributes(agentID, targetDomain, credentialRefHash, status string) SearchAttributes {
	return SearchAttributes{
		AgentID:           agentID,
		TargetDomain:      targetDomain,
		CredentialRefHash: credentialRefHash,
		Status:            status,
	}
}

// ToSearchAttributeUpdates returns the typed updates suitable for
// workflow.UpsertTypedSearchAttributes. Only non-empty fields are included.
func (sa SearchAttributes) ToSearchAttributeUpdates() []temporal.SearchAttributeUpdate {
	var updates []temporal.SearchAttributeUpdate
	if sa.AgentID != "" {
		updates = append(updates, temporal.NewSearchAttributeKeyString(AttrAgentID).ValueSet(sa.AgentID))
	}
	if sa.TargetDomain != "" {
		updates = append(updates, temporal.NewSearchAttributeKeyString(AttrTargetDomain).ValueSet(sa.TargetDomain))
	}
	if sa.CredentialRefHash != "" {
		updates = append(updates, temporal.NewSearchAttributeKeyString(AttrCredentialRefHash).ValueSet(sa.CredentialRefHash))
	}
	if sa.Status != "" {
		updates = append(updates, temporal.NewSearchAttributeKeyString(AttrStatus).ValueSet(sa.Status))
	}
	return updates
}
