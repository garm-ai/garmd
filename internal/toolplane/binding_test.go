package toolplane_test

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	toolv1 "github.com/garm-ai/contracts/garm/tool/v1"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// A grant bound to a task lands on the ledger row (cards-and-tasks §7).
//
// The STS binds a grant to the task it was given on, so the same payment
// asked twice cannot share one approval. Nothing in the chain CHECKS the
// claim — the thing that knows which task is being decided is the caller that
// opened it — but "which calls ran under task X" is a question asked of the
// ledger afterwards, and it is unanswerable unless somebody writes it down.

// bindingGrants is a GrantVerifier that reports a task binding, the way
// internal/grants does once a grant carries the claim.
type bindingGrants struct {
	task string
	err  error
}

func (b *bindingGrants) Verify(
	ctx context.Context, _ *toolplane.Principal, _ toolplane.ToolDef, _ proto.Message,
) error {
	toolplane.NoteGrantBinding(ctx, toolplane.GrantBinding{TaskID: b.task})
	return b.err
}

func TestABoundGrantPutsItsTaskOnTheLedgerRow(t *testing.T) {
	for name, tc := range map[string]struct {
		grants  *bindingGrants
		wantTag string
		wantErr bool
	}{
		"an approval given on a task": {
			grants: &bindingGrants{task: "tsk_01HZY"}, wantTag: "tsk_01HZY",
		},
		// Refused, and still recorded. "An approval naming task X was
		// presented and rejected" and "no approval naming a task was ever
		// presented" are different facts, and only the first is worth waking
		// anybody up for.
		"an approval for a task, refused": {
			grants:  &bindingGrants{task: "tsk_01HZY", err: errors.New("wrong tool")},
			wantTag: "tsk_01HZY", wantErr: true,
		},
		// A grant minted before the STS learned about tasks — every grant in
		// the estate today. Absent, not empty: a column that is always filled
		// distinguishes nothing.
		"an approval bound to no task": {grants: &bindingGrants{}},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &countingRecorder{}
			core := testCore(t, rec, okResolver, withGrants(tc.grants))

			_, err := core.Invoke(context.Background(),
				testPrincipal(toolv1.Clearance_CLEARANCE_CONFIDENTIAL),
				testProcedure, testRequest())
			if tc.wantErr != (err != nil) {
				t.Fatalf("Invoke err = %v, wantErr = %v", err, tc.wantErr)
			}
			if rec.count() != 1 {
				t.Fatalf("%d ledger rows, want 1", rec.count())
			}

			got, present := rec.event().Tags[toolplane.LedgerTagTaskID]
			switch {
			case tc.wantTag == "" && present:
				t.Errorf("the row carries task_id = %q for a grant bound to no task", got)
			case tc.wantTag != "" && got != tc.wantTag:
				t.Errorf("the row carries task_id = %q, want %q", got, tc.wantTag)
			}
		})
	}
}
