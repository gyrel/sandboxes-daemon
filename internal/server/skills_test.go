package server

import (
	"testing"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
)

func TestFromProtoSkillsMapsModes(t *testing.T) {
	for _, tc := range []struct {
		mode localv1.SkillsMode
		want string
	}{
		{localv1.SkillsMode_SKILLS_MODE_OFF, "off"},
		{localv1.SkillsMode_SKILLS_MODE_READONLY, "readonly"},
		{localv1.SkillsMode_SKILLS_MODE_READWRITE, "readwrite"},
		{localv1.SkillsMode(999), ""},
	} {
		got := fromProtoSkills(&localv1.SkillsOptions{Mode: tc.mode, StorePath: "/synthetic"})
		if got == nil || got.Mode != tc.want || got.StorePath != "/synthetic" {
			t.Fatalf("mode %v: got %+v", tc.mode, got)
		}
	}
	if got := fromProtoSkills(nil); got != nil {
		t.Fatalf("nil skills: %+v", got)
	}
}
