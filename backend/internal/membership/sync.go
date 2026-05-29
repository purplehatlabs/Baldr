package membership

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	githubclient "github.com/purplehatlabs/Baldr/internal/github"
	"github.com/purplehatlabs/Baldr/internal/models"
	"go.uber.org/zap"
)

type SyncResult struct {
	OrgMembersUpserted int `json:"org_members_upserted"`
	OrgMembersInactive int `json:"org_members_inactive"`
	TeamLinksUpserted  int `json:"team_links_upserted"`
	TeamLinksRemoved   int `json:"team_links_removed"`
	TeamsProcessed     int `json:"teams_processed"`
}

type Service struct {
	db     *pgxpool.Pool
	github *githubclient.Client
	log    *zap.Logger
}

func NewService(db *pgxpool.Pool, gh *githubclient.Client, log *zap.Logger) *Service {
	return &Service{db: db, github: gh, log: log}
}

func (s *Service) SyncOrg(ctx context.Context, tenantID, orgID uuid.UUID) (*SyncResult, error) {
	start := time.Now()

	var org models.Organization
	err := s.db.QueryRow(ctx, `
		SELECT id, tenant_id, github_org_login, github_app_installation_id
		FROM organizations
		WHERE id = $1 AND tenant_id = $2`,
		orgID, tenantID,
	).Scan(&org.ID, &org.TenantID, &org.GithubOrgLogin, &org.GithubAppInstallationID)
	if err != nil {
		return nil, fmt.Errorf("load org: %w", err)
	}
	if org.GithubAppInstallationID == nil {
		return nil, fmt.Errorf("org has no GitHub App installation")
	}

	members, err := s.github.ListOrgMembers(ctx, tenantID, *org.GithubAppInstallationID, org.GithubOrgLogin)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := time.Now().UTC()
	seen := make(map[int64]uuid.UUID, len(members))
	result := &SyncResult{}

	for _, member := range members {
		var memberID uuid.UUID
		err = tx.QueryRow(ctx, `
			INSERT INTO org_members (id, org_id, tenant_id, github_user_id, github_login, name, avatar_url, is_active, last_synced_at, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8, $8)
			ON CONFLICT (org_id, github_user_id) DO UPDATE SET
				github_login = EXCLUDED.github_login,
				name = EXCLUDED.name,
				avatar_url = EXCLUDED.avatar_url,
				is_active = TRUE,
				last_synced_at = EXCLUDED.last_synced_at
			RETURNING id`,
			uuid.New(), org.ID, tenantID, member.ID, member.Login, member.Name, member.AvatarURL, now,
		).Scan(&memberID)
		if err != nil {
			return nil, fmt.Errorf("upsert org member %s: %w", member.Login, err)
		}
		seen[member.ID] = memberID
		result.OrgMembersUpserted++
	}

	tag, err := tx.Exec(ctx, `
		UPDATE org_members
		SET is_active = FALSE, last_synced_at = $1
		WHERE org_id = $2 AND tenant_id = $3 AND is_active = TRUE
		  AND NOT (github_user_id = ANY($4))`,
		now, org.ID, tenantID, githubIDs(seen),
	)
	if err != nil {
		return nil, fmt.Errorf("deactivate org members: %w", err)
	}
	result.OrgMembersInactive = int(tag.RowsAffected())

	if _, err = tx.Exec(ctx, `
		UPDATE org_members om
		SET user_id = u.id
		FROM users u
		WHERE om.org_id = $1 AND om.tenant_id = $2
		  AND om.user_id IS NULL
		  AND u.tenant_id = om.tenant_id
		  AND u.github_user_id = om.github_user_id`,
		org.ID, tenantID,
	); err != nil {
		return nil, fmt.Errorf("link org members to users: %w", err)
	}

	teamRows, err := tx.Query(ctx, `
		SELECT id, github_team_slug FROM teams WHERE org_id = $1`, org.ID)
	if err != nil {
		return nil, fmt.Errorf("list teams: %w", err)
	}

	type teamRef struct {
		id   uuid.UUID
		slug string
	}
	teams := make([]teamRef, 0)
	for teamRows.Next() {
		var ref teamRef
		if err := teamRows.Scan(&ref.id, &ref.slug); err != nil {
			continue
		}
		teams = append(teams, ref)
	}
	if err := teamRows.Err(); err != nil {
		teamRows.Close()
		return nil, fmt.Errorf("list teams: %w", err)
	}
	teamRows.Close()

	for _, team := range teams {
		teamID := team.id
		teamSlug := team.slug
		result.TeamsProcessed++

		teamMembers, err := s.github.ListTeamMembers(ctx, tenantID, *org.GithubAppInstallationID, org.GithubOrgLogin, teamSlug)
		if err != nil {
			s.log.Warn("list team members failed",
				zap.String("org", org.GithubOrgLogin),
				zap.String("team_slug", teamSlug),
				zap.Error(err),
			)
			continue
		}

		activeLinks := make([]uuid.UUID, 0, len(teamMembers))
		for _, tm := range teamMembers {
			orgMemberID, ok := seen[tm.ID]
			if !ok {
				var fetched uuid.UUID
				err = tx.QueryRow(ctx, `
					SELECT id FROM org_members
					WHERE org_id = $1 AND github_user_id = $2`,
					org.ID, tm.ID,
				).Scan(&fetched)
				if err != nil {
					if err == pgx.ErrNoRows {
						continue
					}
					return nil, fmt.Errorf("resolve org member for team sync: %w", err)
				}
				orgMemberID = fetched
			}

			tag, err := tx.Exec(ctx, `
				INSERT INTO team_members (team_id, org_member_id, last_synced_at)
				VALUES ($1, $2, $3)
				ON CONFLICT (team_id, org_member_id) DO UPDATE SET last_synced_at = EXCLUDED.last_synced_at`,
				teamID, orgMemberID, now,
			)
			if err != nil {
				return nil, fmt.Errorf("upsert team member: %w", err)
			}
			if tag.RowsAffected() > 0 {
				result.TeamLinksUpserted++
			}
			activeLinks = append(activeLinks, orgMemberID)
		}

		tag, err := tx.Exec(ctx, `
			DELETE FROM team_members tm
			USING org_members om
			WHERE tm.team_id = $1
			  AND tm.org_member_id = om.id
			  AND om.org_id = $2
			  AND NOT (tm.org_member_id = ANY($3))`,
			teamID, org.ID, activeLinks,
		)
		if err != nil {
			return nil, fmt.Errorf("prune team members: %w", err)
		}
		result.TeamLinksRemoved += int(tag.RowsAffected())
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}

	s.log.Info("membership sync completed",
		zap.String("org_id", org.ID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.Int("org_members_upserted", result.OrgMembersUpserted),
		zap.Int("org_members_inactive", result.OrgMembersInactive),
		zap.Int("team_links_upserted", result.TeamLinksUpserted),
		zap.Int("team_links_removed", result.TeamLinksRemoved),
		zap.Int("teams_processed", result.TeamsProcessed),
		zap.Duration("duration", time.Since(start)),
	)

	return result, nil
}

func githubIDs(seen map[int64]uuid.UUID) []int64 {
	if len(seen) == 0 {
		return []int64{-1}
	}
	out := make([]int64, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	return out
}
