package server

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/rheic/sandboxes-daemon/internal/oauthsession"
	"github.com/rheic/sandboxes-daemon/internal/service"
)

func TestAccountLoginErrorMapsActionableCauses(t *testing.T) {
	for name, test := range map[string]struct {
		err  error
		want string
	}{
		"credential conflict": {
			err:  service.ErrOAuthCredentialConflict,
			want: "run rsbx logout",
		},
		"host keychain unavailable": {
			err:  service.ErrOAuthHostKeychain,
			want: "host keychain is unavailable",
		},
		"keychain unavailable from sink": {
			err:  oauthsession.ErrHostKeychainUnavailable,
			want: "host keychain is unavailable",
		},
		"unknown cause": {
			err:  errors.New("synthetic"),
			want: "sign-in could not be completed",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := status.Convert(accountLoginError(test.err))
			if got.Code() != codes.FailedPrecondition || !strings.Contains(got.Message(), test.want) {
				t.Fatalf("got %v %q, want FailedPrecondition containing %q", got.Code(), got.Message(), test.want)
			}
			if strings.Contains(got.Message(), "no credentials were returned") {
				t.Fatalf("still reports the misleading sign-in message: %q", got.Message())
			}
		})
	}
}
