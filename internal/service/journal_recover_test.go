package service

import (
	"context"
	"errors"
	"testing"
	"time"

	runtime "github.com/gyrel/sandboxes-runtime"
	"github.com/gyrel/sandboxes-runtime/ctr"
)

type plainBackend struct{}

func (plainBackend) Capabilities(context.Context) (runtime.Capabilities, error) {
	return runtime.Capabilities{}, nil
}
func (plainBackend) Create(context.Context, runtime.Config) (runtime.Handle, error) {
	return runtime.Handle{}, nil
}
func (plainBackend) Start(context.Context, runtime.Handle) error               { return nil }
func (plainBackend) Stop(context.Context, runtime.Handle, time.Duration) error { return nil }
func (plainBackend) Delete(context.Context, runtime.Handle) error              { return nil }
func (plainBackend) Handle(string) runtime.Handle                              { return runtime.Handle{} }

type recoveringBackend struct {
	plainBackend
	findings []ctr.JournalFinding
	err      error
}

func (b recoveringBackend) Recover(context.Context) ([]ctr.JournalFinding, error) {
	return b.findings, b.err
}

func TestRecoverRuntimeJournalNoCapability(t *testing.T) {
	svc := &Service{backend: plainBackend{}}
	summaries, err := svc.RecoverRuntimeJournal(context.Background())
	if err != nil || len(summaries) != 0 {
		t.Fatalf("noop backend: %v %v", summaries, err)
	}
}

func TestRecoverRuntimeJournalSummarizesAndPropagates(t *testing.T) {
	boom := errors.New("state dir unreadable")
	svc := &Service{backend: recoveringBackend{
		findings: []ctr.JournalFinding{{ID: "gyrel-dev", Reason: "foreign"}},
		err:      boom,
	}}
	summaries, err := svc.RecoverRuntimeJournal(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("systemic err = %v", err)
	}
	if len(summaries) != 1 || summaries[0] != "journal gyrel-dev: foreign" {
		t.Fatalf("summaries = %v", summaries)
	}
}
