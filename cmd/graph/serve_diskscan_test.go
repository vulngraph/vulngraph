package main

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/diskscan"
)

func TestDiskScanActor(t *testing.T) {
	admin := auth.ContextWithUser(context.Background(), auth.User{ID: "u1", Role: auth.RoleAdmin})
	viewer := auth.ContextWithUser(context.Background(), auth.User{ID: "u2", Role: auth.RoleViewer})
	viaKey := auth.ContextWithAPIKey(admin, auth.APIKeyRecord{ID: "k1", UserID: "u1"})

	require.Equal(t, diskscan.Actor{ID: "u1", Admin: true}, diskScanActor(admin))
	require.Equal(t, diskscan.Actor{ID: "u2"}, diskScanActor(viewer))
	require.Equal(t, diskscan.Actor{ID: "u1", Admin: true, ViaAPIKey: true}, diskScanActor(viaKey))
	require.False(t, diskScanActor(context.Background()).Admin, "no identity is never an admin")
}

func TestMapConnectorErr(t *testing.T) {
	cases := map[error]error{
		connector.ErrNotFound:             diskscan.ErrNotFound,
		connector.ErrDiskScanForbidden:    diskscan.ErrForbidden,
		connector.ErrDiskScanInvalidMode:  diskscan.ErrInvalid,
		connector.ErrDiskScanConfirmation: diskscan.ErrConfirmation,
		connector.ErrDiskScanUnsupported:  diskscan.ErrUnsupported,
		connector.ErrDiskScanRoleMissing:  diskscan.ErrRoleMissing,
		connector.ErrDiskScanRoleShared:   diskscan.ErrRoleShared,
	}
	for in, want := range cases {
		require.ErrorIs(t, mapConnectorErr(in), want, in.Error())
	}
	other := errors.New("db down")
	require.Equal(t, other, mapConnectorErr(other))
}
