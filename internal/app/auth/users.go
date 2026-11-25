package auth

import (
	"context"
	"fmt"
	"time"
)

// UserUpdate is an admin's change to another user. Nil fields are unchanged.
type UserUpdate struct {
	Role     *Role
	Disabled *bool
}

// UpdateUser applies an admin's role and/or disabled change to targetID.
// Disabling also deletes the user's sessions in the same transaction (they are
// already refused by the session lookup; deleting them keeps the table honest).
// Guards:
//   - an admin never changes their own row (ErrSelfAction) — locking yourself
//     out is never what a click on your own row meant;
//   - the last active admin can be neither demoted nor disabled (ErrLastAdmin).
func (s *Service) UpdateUser(ctx context.Context, actorID, targetID string, upd UserUpdate) (User, error) {
	if actorID == targetID {
		return User{}, ErrSelfAction
	}
	if upd.Role != nil && !upd.Role.Valid() {
		return User{}, ErrInvalidRole
	}
	target, err := s.repo.GetUserByID(ctx, targetID)
	if err != nil {
		return User{}, fmt.Errorf("UpdateUser: %w", err)
	}
	demoting := upd.Role != nil && *upd.Role != RoleAdmin
	disabling := upd.Disabled != nil && *upd.Disabled && target.DisabledAt == nil
	if demoting || disabling {
		if err := s.ensureNotLastAdmin(ctx, target); err != nil {
			return User{}, fmt.Errorf("UpdateUser: %w", err)
		}
	}
	if upd.Role != nil {
		if err := s.setRole(ctx, target, *upd.Role); err != nil {
			return User{}, fmt.Errorf("UpdateUser: %w", err)
		}
	}
	if upd.Disabled != nil {
		var at *time.Time
		if *upd.Disabled {
			now := s.now()
			at = &now
			if target.DisabledAt != nil {
				at = target.DisabledAt // keep the original offboarding time
			}
		}
		n, err := s.repo.SetUserDisabledAt(ctx, targetID, at, *upd.Disabled)
		if err != nil {
			return User{}, fmt.Errorf("UpdateUser: %w", err)
		}
		details := map[string]any{"email": target.Email, "was_disabled": target.DisabledAt != nil}
		action := AuditActionUserEnable
		if *upd.Disabled {
			action, details["sessions_revoked"] = AuditActionUserDisable, n
		}
		s.record(ctx, action, targetID, details)
	}
	updated, err := s.repo.GetUserByID(ctx, targetID)
	if err != nil {
		return User{}, fmt.Errorf("UpdateUser: %w", err)
	}
	return updated, nil
}

// setRole stores target's new role. Under REQUIRE_ADMIN_TOTP a promotion to
// admin also ends target's sessions, in the same transaction: one signed in by password without a
// TOTP code must not carry the admin role.
func (s *Service) setRole(ctx context.Context, target User, role Role) error {
	revoke := s.requireAdminTOTP && role == RoleAdmin && target.Role != RoleAdmin
	n, err := s.repo.SetUserRole(ctx, target.ID, role, revoke)
	if err != nil {
		return fmt.Errorf("setRole: %w", err)
	}
	details := map[string]any{"email": target.Email, "before": string(target.Role), "after": string(role)}
	if revoke {
		details["sessions_revoked"] = n
	}
	s.record(ctx, AuditActionUserRoleChange, target.ID, details)
	return nil
}

// DeleteUser removes targetID with its sessions and API keys. Prefer
// disabling: audit history refers to users by id.
func (s *Service) DeleteUser(ctx context.Context, actorID, targetID string) error {
	if actorID == targetID {
		return ErrSelfAction
	}
	target, err := s.repo.GetUserByID(ctx, targetID)
	if err != nil {
		return fmt.Errorf("DeleteUser: %w", err)
	}
	if err := s.ensureNotLastAdmin(ctx, target); err != nil {
		return fmt.Errorf("DeleteUser: %w", err)
	}
	if err := s.repo.DeleteUser(ctx, targetID); err != nil {
		return fmt.Errorf("DeleteUser: %w", err)
	}
	s.record(ctx, AuditActionUserDelete, targetID, map[string]any{"email": target.Email, "role": string(target.Role)})
	return nil
}

// RevokeSessions signs targetID out everywhere and returns how many sessions
// ended. API keys are separate credentials and are not touched.
func (s *Service) RevokeSessions(ctx context.Context, actorID, targetID string) (int64, error) {
	if actorID == targetID {
		return 0, ErrSelfAction
	}
	target, err := s.repo.GetUserByID(ctx, targetID)
	if err != nil {
		return 0, fmt.Errorf("RevokeSessions: %w", err)
	}
	n, err := s.repo.DeleteUserSessions(ctx, targetID)
	if err != nil {
		return 0, fmt.Errorf("RevokeSessions: %w", err)
	}
	s.record(ctx, AuditActionSessionsRevoke, targetID, map[string]any{"email": target.Email, "sessions_revoked": n})
	return n, nil
}

// ensureNotLastAdmin refuses to remove target's admin access when it is the
// only active admin left.
func (s *Service) ensureNotLastAdmin(ctx context.Context, target User) error {
	if target.Role != RoleAdmin || target.DisabledAt != nil {
		return nil
	}
	n, err := s.repo.CountActiveAdmins(ctx)
	if err != nil {
		return fmt.Errorf("ensureNotLastAdmin: %w", err)
	}
	if n <= 1 {
		return ErrLastAdmin
	}
	return nil
}
