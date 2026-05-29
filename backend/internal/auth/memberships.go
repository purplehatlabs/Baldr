package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/models"
)

var (
	ErrMembershipNotFound = errors.New("tenant membership not found")
	ErrMembershipInactive = errors.New("tenant membership is inactive")
	ErrInviteNotFound     = errors.New("tenant invite not found")
	ErrInviteExpired      = errors.New("tenant invite expired")
	ErrInviteEmailMismatch = errors.New("invite email does not match authenticated user")
)

const defaultInviteTTL = 7 * 24 * time.Hour

type MembershipStore struct {
	db *pgxpool.Pool
}

func NewMembershipStore(db *pgxpool.Pool) *MembershipStore {
	return &MembershipStore{db: db}
}

func (s *MembershipStore) UpsertActive(ctx context.Context, tenantID, userID uuid.UUID, role models.UserRole) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO tenant_memberships (tenant_id, user_id, role, status, token_version, created_at, updated_at)
		VALUES ($1, $2, $3, 'active', 1, NOW(), NOW())
		ON CONFLICT (tenant_id, user_id) DO UPDATE
		SET role = EXCLUDED.role,
		    status = 'active',
		    updated_at = NOW()`,
		tenantID, userID, role,
	)
	return err
}

func (s *MembershipStore) GetActive(ctx context.Context, tenantID, userID uuid.UUID) (*models.TenantMembership, error) {
	var m models.TenantMembership
	err := s.db.QueryRow(ctx, `
		SELECT id, tenant_id, user_id, role, status, token_version, created_at, updated_at
		FROM tenant_memberships
		WHERE tenant_id = $1 AND user_id = $2 AND status = 'active'`,
		tenantID, userID,
	).Scan(&m.ID, &m.TenantID, &m.UserID, &m.Role, &m.Status, &m.TokenVersion, &m.CreatedAt, &m.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrMembershipNotFound
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *MembershipStore) ValidateSession(ctx context.Context, tenantID, userID uuid.UUID, tokenVersion int) error {
	m, err := s.GetActive(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if m.TokenVersion != tokenVersion {
		return ErrMembershipNotFound
	}
	return nil
}

func (s *MembershipStore) ListAccessibleTenants(ctx context.Context, userID uuid.UUID) ([]models.TenantSummary, error) {
	rows, err := s.db.Query(ctx, `
		SELECT t.id, t.name, t.slug, tm.role, tm.status
		FROM tenant_memberships tm
		JOIN tenants t ON t.id = tm.tenant_id
		WHERE tm.user_id = $1 AND tm.status = 'active'
		ORDER BY t.name`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.TenantSummary
	for rows.Next() {
		var ts models.TenantSummary
		if err := rows.Scan(&ts.TenantID, &ts.TenantName, &ts.TenantSlug, &ts.Role, &ts.Status); err != nil {
			return nil, err
		}
		ts.IsActive = true
		out = append(out, ts)
	}
	return out, rows.Err()
}

func (s *MembershipStore) ListMembers(ctx context.Context, tenantID uuid.UUID) ([]MemberListItem, error) {
	rows, err := s.db.Query(ctx, `
		SELECT tm.id, tm.user_id, u.email, u.name, u.avatar_url, tm.role, tm.status, tm.created_at, tm.updated_at
		FROM tenant_memberships tm
		JOIN users u ON u.id = tm.user_id
		WHERE tm.tenant_id = $1
		ORDER BY u.name, u.email`,
		tenantID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MemberListItem
	for rows.Next() {
		var item MemberListItem
		if err := rows.Scan(
			&item.MembershipID, &item.UserID, &item.Email, &item.Name, &item.AvatarURL,
			&item.Role, &item.Status, &item.CreatedAt, &item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

type MemberListItem struct {
	MembershipID uuid.UUID               `json:"membership_id"`
	UserID       uuid.UUID               `json:"user_id"`
	Email        string                  `json:"email"`
	Name         string                  `json:"name"`
	AvatarURL    string                  `json:"avatar_url"`
	Role         models.UserRole         `json:"role"`
	Status       models.MembershipStatus `json:"status"`
	CreatedAt    time.Time               `json:"created_at"`
	UpdatedAt    time.Time               `json:"updated_at"`
}

func (s *MembershipStore) UpdateMember(ctx context.Context, tenantID, membershipID uuid.UUID, role *models.UserRole, status *models.MembershipStatus) (*MemberListItem, error) {
	if role == nil && status == nil {
		return nil, errors.New("no fields to update")
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT user_id FROM tenant_memberships
		WHERE id = $1 AND tenant_id = $2`,
		membershipID, tenantID,
	).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrMembershipNotFound
	}
	if err != nil {
		return nil, err
	}

	setParts := []string{"updated_at = NOW()", "token_version = token_version + 1"}
	args := []any{membershipID, tenantID}
	argIdx := 3

	if role != nil {
		setParts = append(setParts, "role = $"+itoa(argIdx))
		args = append(args, *role)
		argIdx++
	}
	if status != nil {
		setParts = append(setParts, "status = $"+itoa(argIdx))
		args = append(args, *status)
		argIdx++
	}

	query := "UPDATE tenant_memberships SET " + strings.Join(setParts, ", ") +
		" WHERE id = $1 AND tenant_id = $2"
	if _, err = tx.Exec(ctx, query, args...); err != nil {
		return nil, err
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}

	var item MemberListItem
	err = s.db.QueryRow(ctx, `
		SELECT tm.id, tm.user_id, u.email, u.name, u.avatar_url, tm.role, tm.status, tm.created_at, tm.updated_at
		FROM tenant_memberships tm
		JOIN users u ON u.id = tm.user_id
		WHERE tm.id = $1 AND tm.tenant_id = $2`,
		membershipID, tenantID,
	).Scan(
		&item.MembershipID, &item.UserID, &item.Email, &item.Name, &item.AvatarURL,
		&item.Role, &item.Status, &item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &item, nil
}

func itoa(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	return string(buf[i:])
}

type InviteStore struct {
	db *pgxpool.Pool
}

func NewInviteStore(db *pgxpool.Pool) *InviteStore {
	return &InviteStore{db: db}
}

type InviteListItem struct {
	ID        uuid.UUID          `json:"id"`
	Email     string             `json:"email"`
	Role      models.UserRole    `json:"role"`
	Status    models.InviteStatus `json:"status"`
	ExpiresAt time.Time          `json:"expires_at"`
	CreatedAt time.Time          `json:"created_at"`
	InviteURL string             `json:"invite_url,omitempty"`
}

func (s *InviteStore) Create(ctx context.Context, tenantID, invitedBy uuid.UUID, email string, role models.UserRole, frontendBaseURL string) (*InviteListItem, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	token, err := randomInviteToken()
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().UTC().Add(defaultInviteTTL)

	var item InviteListItem
	err = s.db.QueryRow(ctx, `
		INSERT INTO tenant_invites (tenant_id, email, role, token, invited_by, status, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, 'pending', $6, NOW())
		RETURNING id, email, role, status, expires_at, created_at`,
		tenantID, email, role, token, invitedBy, expiresAt,
	).Scan(&item.ID, &item.Email, &item.Role, &item.Status, &item.ExpiresAt, &item.CreatedAt)
	if err != nil {
		return nil, err
	}
	if frontendBaseURL != "" {
		item.InviteURL = strings.TrimRight(frontendBaseURL, "/") + "/invite/" + token
	}
	return &item, nil
}

func (s *InviteStore) ListPending(ctx context.Context, tenantID uuid.UUID) ([]InviteListItem, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, email, role, status, expires_at, created_at
		FROM tenant_invites
		WHERE tenant_id = $1 AND status = 'pending' AND expires_at > NOW()
		ORDER BY created_at DESC`,
		tenantID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []InviteListItem
	for rows.Next() {
		var item InviteListItem
		if err := rows.Scan(&item.ID, &item.Email, &item.Role, &item.Status, &item.ExpiresAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *InviteStore) Revoke(ctx context.Context, tenantID, inviteID uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `
		UPDATE tenant_invites SET status = 'revoked'
		WHERE id = $1 AND tenant_id = $2 AND status = 'pending'`,
		inviteID, tenantID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInviteNotFound
	}
	return nil
}

func (s *InviteStore) Accept(ctx context.Context, token string, userID uuid.UUID, userEmail string) (*models.TenantMembership, error) {
	userEmail = strings.TrimSpace(strings.ToLower(userEmail))

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var invite models.TenantInvite
	err = tx.QueryRow(ctx, `
		SELECT id, tenant_id, email, role, status, expires_at
		FROM tenant_invites
		WHERE token = $1`,
		token,
	).Scan(&invite.ID, &invite.TenantID, &invite.Email, &invite.Role, &invite.Status, &invite.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInviteNotFound
	}
	if err != nil {
		return nil, err
	}
	if invite.Status != models.InvitePending {
		return nil, ErrInviteNotFound
	}
	if time.Now().UTC().After(invite.ExpiresAt) {
		_, _ = tx.Exec(ctx, `UPDATE tenant_invites SET status = 'expired' WHERE id = $1`, invite.ID)
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, ErrInviteExpired
	}
	if invite.Email != userEmail {
		return nil, ErrInviteEmailMismatch
	}

	var membership models.TenantMembership
	err = tx.QueryRow(ctx, `
		INSERT INTO tenant_memberships (tenant_id, user_id, role, status, token_version, created_at, updated_at)
		VALUES ($1, $2, $3, 'active', 1, NOW(), NOW())
		ON CONFLICT (tenant_id, user_id) DO UPDATE
		SET role = EXCLUDED.role,
		    status = 'active',
		    updated_at = NOW()
		RETURNING id, tenant_id, user_id, role, status, token_version, created_at, updated_at`,
		invite.TenantID, userID, invite.Role,
	).Scan(
		&membership.ID, &membership.TenantID, &membership.UserID, &membership.Role,
		&membership.Status, &membership.TokenVersion, &membership.CreatedAt, &membership.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if _, err = tx.Exec(ctx, `
		UPDATE tenant_invites
		SET status = 'accepted', accepted_at = $1, accepted_by = $2
		WHERE id = $3`,
		now, userID, invite.ID,
	); err != nil {
		return nil, err
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &membership, nil
}

func randomInviteToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
