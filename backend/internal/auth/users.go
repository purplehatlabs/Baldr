package auth

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/models"
)

const (
	AuthProviderGoogle = "google"
	AuthProviderGitHub = "github"
	AuthProviderDev    = "dev"
)

var ErrMissingEmail = errors.New("authenticated user has no email")

type UserStore struct {
	db *pgxpool.Pool
}

func NewUserStore(db *pgxpool.Pool) *UserStore {
	return &UserStore{db: db}
}

func (s *UserStore) UpsertGoogleUser(ctx context.Context, info *GoogleUserInfo) (*models.User, error) {
	var user models.User
	err := s.db.QueryRow(ctx,
		`SELECT id, tenant_id, email, name, avatar_url, role, created_at
		 FROM users WHERE google_id = $1`,
		info.ID,
	).Scan(&user.ID, &user.TenantID, &user.Email, &user.Name, &user.AvatarURL, &user.Role, &user.CreatedAt)
	if err == nil {
		_, _ = s.db.Exec(ctx,
			`UPDATE users
			 SET name = $1, avatar_url = $2, email = $3,
			     auth_provider = CASE WHEN auth_provider = $4 THEN $5 ELSE auth_provider END
			 WHERE id = $6`,
			info.Name, info.Picture, info.Email,
			AuthProviderGitHub, AuthProviderGoogle, user.ID,
		)
		user.Name = info.Name
		user.AvatarURL = info.Picture
		user.Email = info.Email
		return &user, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	err = s.db.QueryRow(ctx,
		`SELECT id, tenant_id, email, name, avatar_url, role, created_at
		 FROM users WHERE lower(email) = lower($1)`,
		info.Email,
	).Scan(&user.ID, &user.TenantID, &user.Email, &user.Name, &user.AvatarURL, &user.Role, &user.CreatedAt)
	if err == nil {
		_, err = s.db.Exec(ctx,
			`UPDATE users
			 SET google_id = $1, name = $2, avatar_url = $3, email = $4,
			     auth_provider = CASE WHEN auth_provider = $5 THEN $6 ELSE auth_provider END
			 WHERE id = $7`,
			info.ID, info.Name, info.Picture, info.Email,
			AuthProviderGitHub, AuthProviderGoogle, user.ID,
		)
		if err != nil {
			return nil, err
		}
		user.Name = info.Name
		user.AvatarURL = info.Picture
		user.Email = info.Email
		return &user, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tenantID := uuid.New()
	userID := uuid.New()
	if _, err = tx.Exec(ctx,
		`INSERT INTO tenants (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		tenantID, info.Email, tenantID.String(),
	); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx,
		`INSERT INTO users (id, tenant_id, email, google_id, name, avatar_url, role, auth_provider, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
		userID, tenantID, info.Email, info.ID, info.Name, info.Picture, models.RoleOwner, AuthProviderGoogle,
	); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}

	return &models.User{
		ID: userID, TenantID: tenantID,
		Email: info.Email, Name: info.Name, AvatarURL: info.Picture, Role: models.RoleOwner,
	}, nil
}

func (s *UserStore) UpsertGitHubUser(ctx context.Context, info *GitHubUserInfo) (*models.User, error) {
	if info.Email == "" {
		return nil, ErrMissingEmail
	}

	var user models.User
	err := s.db.QueryRow(ctx,
		`SELECT id, tenant_id, email, name, avatar_url, role, created_at
		 FROM users WHERE github_user_id = $1`,
		info.ID,
	).Scan(&user.ID, &user.TenantID, &user.Email, &user.Name, &user.AvatarURL, &user.Role, &user.CreatedAt)
	if err == nil {
		return s.refreshGitHubUser(ctx, &user, info)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	err = s.db.QueryRow(ctx,
		`SELECT id, tenant_id, email, name, avatar_url, role, created_at
		 FROM users WHERE lower(email) = lower($1)`,
		info.Email,
	).Scan(&user.ID, &user.TenantID, &user.Email, &user.Name, &user.AvatarURL, &user.Role, &user.CreatedAt)
	if err == nil {
		_, err = s.db.Exec(ctx,
			`UPDATE users
			 SET github_user_id = $1, github_login = $2, name = $3, avatar_url = $4,
			     auth_provider = CASE WHEN auth_provider = $5 THEN $6 ELSE auth_provider END
			 WHERE id = $7`,
			info.ID, info.Login, info.Name, info.AvatarURL,
			AuthProviderGoogle, AuthProviderGitHub, user.ID,
		)
		if err != nil {
			return nil, err
		}
		s.linkOrgMembers(ctx, user.TenantID, info.ID, user.ID)
		user.Name = info.Name
		user.AvatarURL = info.AvatarURL
		user.Email = info.Email
		return &user, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tenantID := uuid.New()
	userID := uuid.New()
	if _, err = tx.Exec(ctx,
		`INSERT INTO tenants (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		tenantID, info.Login, tenantID.String(),
	); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx,
		`INSERT INTO users (id, tenant_id, email, github_user_id, github_login, name, avatar_url, role, auth_provider, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())`,
		userID, tenantID, info.Email, info.ID, info.Login, info.Name, info.AvatarURL, models.RoleOwner, AuthProviderGitHub,
	); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}

	user = models.User{
		ID: userID, TenantID: tenantID,
		Email: info.Email, Name: info.Name, AvatarURL: info.AvatarURL, Role: models.RoleOwner,
	}
	s.linkOrgMembers(ctx, tenantID, info.ID, userID)
	return &user, nil
}

func (s *UserStore) refreshGitHubUser(ctx context.Context, user *models.User, info *GitHubUserInfo) (*models.User, error) {
	_, err := s.db.Exec(ctx,
		`UPDATE users
		 SET github_login = $1, name = $2, avatar_url = $3, email = $4, auth_provider = $5
		 WHERE id = $6`,
		info.Login, info.Name, info.AvatarURL, info.Email, AuthProviderGitHub, user.ID,
	)
	if err != nil {
		return nil, err
	}
	s.linkOrgMembers(ctx, user.TenantID, info.ID, user.ID)
	user.Name = info.Name
	user.AvatarURL = info.AvatarURL
	user.Email = info.Email
	return user, nil
}

func (s *UserStore) linkOrgMembers(ctx context.Context, tenantID uuid.UUID, githubUserID int64, userID uuid.UUID) {
	_, _ = s.db.Exec(ctx,
		`UPDATE org_members
		 SET user_id = $1
		 WHERE tenant_id = $2 AND github_user_id = $3 AND (user_id IS NULL OR user_id = $1)`,
		userID, tenantID, githubUserID,
	)
}
