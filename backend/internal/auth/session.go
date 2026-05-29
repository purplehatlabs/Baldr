package auth

import (
	"context"

	"github.com/google/uuid"
	"github.com/purplehatlabs/Baldr/internal/models"
)

// SessionTokens issues JWT cookies using active membership as source of truth.
type SessionTokens struct {
	tokens      *TokenService
	memberships *MembershipStore
}

func NewSessionTokens(tokens *TokenService, memberships *MembershipStore) *SessionTokens {
	return &SessionTokens{tokens: tokens, memberships: memberships}
}

func (s *SessionTokens) IssueForUser(ctx context.Context, user *models.User) (string, error) {
	membership, err := s.resolveLoginMembership(ctx, user.ID, user.TenantID)
	if err != nil {
		return "", err
	}
	return s.tokens.Issue(user.ID, membership.TenantID, user.Email, string(membership.Role), membership.TokenVersion)
}

func (s *SessionTokens) IssueForMembership(ctx context.Context, user *models.User, membership *models.TenantMembership) (string, error) {
	return s.tokens.Issue(user.ID, membership.TenantID, user.Email, string(membership.Role), membership.TokenVersion)
}

func (s *SessionTokens) resolveLoginMembership(ctx context.Context, userID, preferredTenantID uuid.UUID) (*models.TenantMembership, error) {
	if preferredTenantID != uuid.Nil {
		if m, err := s.memberships.GetActive(ctx, preferredTenantID, userID); err == nil {
			return m, nil
		}
	}

	tenants, err := s.memberships.ListAccessibleTenants(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(tenants) == 0 {
		return nil, ErrMembershipNotFound
	}
	return s.memberships.GetActive(ctx, tenants[0].TenantID, userID)
}
