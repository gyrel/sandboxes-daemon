package server

import (
	"context"
	"testing"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCreateRejectsSkillsWithoutRaceSafeRuntime(t *testing.T) {
	server := NewSandbox(nil)
	for _, mode := range []localv1.SkillsMode{
		localv1.SkillsMode_SKILLS_MODE_UNSPECIFIED,
		localv1.SkillsMode_SKILLS_MODE_OFF,
		localv1.SkillsMode_SKILLS_MODE_READONLY,
		localv1.SkillsMode_SKILLS_MODE_READWRITE,
		localv1.SkillsMode(999),
	} {
		_, err := server.Create(context.Background(), &localv1.CreateRequest{Skills: &localv1.SkillsOptions{Mode: mode, StorePath: "/synthetic/skills"}})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("mode=%v: got %v", mode, err)
		}
	}
}
