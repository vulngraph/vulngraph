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

// UserAdminRepo is the state accessed while the administrator invariant is locked.
type UserAdminRepo interface {
	GetUserByID(context.Context, string) (User, error)
	SetUserRole(context.Context, string, Role, bool) (int64, error)
	SetUserDisabledAt(context.Context, string, *time.Time, bool) (int64, error)
	DeleteUser(context.Context, string) error
	DeleteUserSessions(context.Context, string) (int64, error)
	CountActiveAdmins(context.Context) (int64, error)
}

// UpdateUser applies all changes under the same lock as the last-admin check.
// Promotion under REQUIRE_ADMIN_TOTP and disablement also revoke sessions in
// that transaction. Audit records describe only successfully committed changes.
func (s *Service) UpdateUser(ctx context.Context, actorID, targetID string, upd UserUpdate) (User, error) {
	if actorID == targetID {
		return User{}, ErrSelfAction
	}
	if upd.Role != nil && !upd.Role.Valid() {
		return User{}, ErrInvalidRole
	}
	var target, updated User
	var roleRevoked, disabledRevoked int64
	var revokePromotion bool
	err := s.repo.WithUserAdministration(ctx, func(repo UserAdminRepo) error {
		var err error
		target, err = repo.GetUserByID(ctx, targetID)
		if err != nil {
			return fmt.Errorf("read user: %w", err)
		}
		demoting := upd.Role != nil && *upd.Role != RoleAdmin
		disabling := upd.Disabled != nil && *upd.Disabled && target.DisabledAt == nil
		if demoting || disabling {
			if err := ensureNotLastAdmin(ctx, repo, target); err != nil {
				return err
			}
		}
		if upd.Role != nil {
			revokePromotion = s.requireAdminTOTP && *upd.Role == RoleAdmin && target.Role != RoleAdmin
			roleRevoked, err = repo.SetUserRole(ctx, targetID, *upd.Role, revokePromotion)
			if err != nil {
				return fmt.Errorf("set role: %w", err)
			}
		}
		if upd.Disabled != nil {
			var at *time.Time
			if *upd.Disabled {
				now := s.now()
				at = &now
				if target.DisabledAt != nil {
					at = target.DisabledAt
				}
			}
			disabledRevoked, err = repo.SetUserDisabledAt(ctx, targetID, at, *upd.Disabled)
			if err != nil {
				return fmt.Errorf("set disabled: %w", err)
			}
		}
		updated, err = repo.GetUserByID(ctx, targetID)
		if err != nil {
			return fmt.Errorf("read updated user: %w", err)
		}
		return nil
	})
	if err != nil {
		return User{}, fmt.Errorf("UpdateUser: %w", err)
	}
	if upd.Role != nil {
		details := map[string]any{"email": target.Email, "before": string(target.Role), "after": string(*upd.Role)}
		if revokePromotion {
			details["sessions_revoked"] = roleRevoked
		}
		s.record(ctx, AuditActionUserRoleChange, targetID, details)
	}
	if upd.Disabled != nil {
		details := map[string]any{"email": target.Email, "was_disabled": target.DisabledAt != nil}
		action := AuditActionUserEnable
		if *upd.Disabled {
			action, details["sessions_revoked"] = AuditActionUserDisable, disabledRevoked
		}
		s.record(ctx, action, targetID, details)
	}
	return updated, nil
}

// DeleteUser preserves the last active administrator and commits before auditing.
func (s *Service) DeleteUser(ctx context.Context, actorID, targetID string) error {
	if actorID == targetID {
		return ErrSelfAction
	}
	var target User
	err := s.repo.WithUserAdministration(ctx, func(repo UserAdminRepo) error {
		var err error
		target, err = repo.GetUserByID(ctx, targetID)
		if err != nil {
			return fmt.Errorf("read user: %w", err)
		}
		if err := ensureNotLastAdmin(ctx, repo, target); err != nil {
			return err
		}
		return repo.DeleteUser(ctx, targetID)
	})
	if err != nil {
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
func ensureNotLastAdmin(ctx context.Context, repo UserAdminRepo, target User) error {
	if target.Role != RoleAdmin || target.DisabledAt != nil {
		return nil
	}
	n, err := repo.CountActiveAdmins(ctx)
	if err != nil {
		return fmt.Errorf("ensureNotLastAdmin: %w", err)
	}
	if n <= 1 {
		return ErrLastAdmin
	}
	return nil
}
