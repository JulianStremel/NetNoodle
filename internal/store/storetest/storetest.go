// Package storetest defines the backend-independent persistence contract.
package storetest

import (
	"testing"

	"github.com/JulianStremel/netnoodle/internal/store"
)

// Run tests a backend. open must return an empty, independent store on every
// call and arrange for it to be closed with t.Cleanup. Tests use only Store
// and the real inventory resolver; they never inspect backend internals.
func Run(t *testing.T, open func(t *testing.T) store.Store) {
	t.Helper()
	tests := []struct {
		name string
		run  func(*testing.T, func(*testing.T) store.Store)
	}{
		{"UsersAndSessions", testUsersAndSessions},
		{"ProposalsLifecycle", testProposalsLifecycle},
		{"ConcurrentProposalUpsertAndDecision", testConcurrentProposalUpsertAndDecision},
		{"TagsSettingsAndMerge", testTagsSettingsAndMerge},
		{"TagUnionLimitIsAtomic", testTagUnionLimitIsAtomic},
		{"TargetProvenanceIsPinnedAndSurvivesMerge", testTargetProvenanceIsPinnedAndSurvivesMerge},
		{"AgentChildMACRequiresIndependentReporter", testAgentChildMACRequiresIndependentReporter},
		{"RecentDeviceClaimsExactDeviceAndWindow", testRecentDeviceClaimsExactDeviceAndWindow},
		{"SnapshotAtAutoAndApprovalAndMergeReset", testSnapshotAtAutoAndApprovalAndMergeReset},
		{"ApprovalAndNoActorExpireWithoutOrder", testApprovalAndNoActorExpireWithoutOrder},
		{"MovedAutoProposalSurvivesMutableCollision", testMovedAutoProposalSurvivesMutableCollision},
		{"SameDeviceTwice", testSameDeviceTwice},
		{"DHCPMoveCreatesNewDevice", testDHCPMoveCreatesNewDevice},
		{"WeakMatchThenStrong", testWeakMatchThenStrong},
		{"StrongCollisionMerges", testStrongCollisionMerges},
		{"LocalMACIsWeak", testLocalMACIsWeak},
		{"ChildrenAndCompleteReports", testChildrenAndCompleteReports},
		{"ParentPlaceholder", testParentPlaceholder},
		{"SkipsEntitiesWithoutIdentifiers", testSkipsEntitiesWithoutIdentifiers},
		{"AgentNoMergeOrStealing", testAgentNoMergeOrStealing},
		{"AgentChildrenScoping", testAgentChildrenScoping},
		{"AgentMaxHostChildren", testAgentMaxHostChildren},
		{"ResolverMergeMovesTagsProposalsOrders", testResolverMergeMovesTagsProposalsOrders},
		{"InventoryTransactionRollback", testInventoryTransactionRollback},
		{"ResolverIdentifierProvenance", testResolverIdentifierProvenance},
		{"FindingsSyncFiltersExposureAndStats", testFindingsSyncFiltersExposureAndStats},
		{"OrderExactlyOnePerProposal", testOrderExactlyOnePerProposal},
		{"OrderResultOwnershipAndIdempotence", testOrderResultOwnershipAndIdempotence},
		{"OrderConcurrentResults", testOrderConcurrentResults},
		{"OrderLateResultGrace", testOrderLateResultGrace},
		{"OrderRevertSchedulingAndAttempts", testOrderRevertSchedulingAndAttempts},
		{"OrderRevertSuccess", testOrderRevertSuccess},
		{"OrderUncertainHandling", testOrderUncertainHandling},
		{"OrderRetentionPreservesRecovery", testOrderRetentionPreservesRecovery},
		{"KillSwitchCancelsQueuedOrders", testKillSwitchCancelsQueuedOrders},
		{"PasswordChangeDeletesSessions", testPasswordChangeDeletesSessions},
		{"EnrollmentAtomicity", testEnrollmentAtomicity},
		{"EnrollmentExactlyOneWins", testEnrollmentExactlyOneWins},
		{"PeerNameExactlyOneWins", testPeerNameExactlyOneWins},
		{"EnrollmentAllowInsideTransaction", testEnrollmentAllowInsideTransaction},
		{"PullPairingCodeExactlyOnce", testPullPairingCodeExactlyOnce},
		{"SettingsAndEventRetention", testSettingsAndEventRetention},
		{"ProposalMutableKey", testProposalMutableKey},
		{"ProposalDecisionDeadline", testProposalDecisionDeadline},
		{"ProposalRetention", testProposalRetention},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { tt.run(t, open) })
	}
}
