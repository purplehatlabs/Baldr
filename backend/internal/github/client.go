package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	gogithub "github.com/google/go-github/v63/github"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/crypto"
)

// ErrNoTenantConfig is returned when a tenant has no GitHub App config persisted.
var ErrNoTenantConfig = errors.New("tenant has no GitHub App configured; upload PEM in Settings")

// ErrInstallationNotFound wraps a 404 from GitHub when refreshing an
// installation access token. The most common cause is mixing up App ID and
// Installation ID, or pointing to an installation that doesn't belong to the
// configured App.
var ErrInstallationNotFound = errors.New("github installation not found")

// classifyTokenError converts opaque ghinstallation errors into our sentinel
// types when possible. Falls back to the original error otherwise.
func classifyTokenError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "access_tokens") && strings.Contains(msg, "404 Not Found") {
		return fmt.Errorf("%w: %s", ErrInstallationNotFound, msg)
	}
	return err
}

// Client wraps GitHub operations. Credentials are loaded per-tenant from the
// database; the PEM is encrypted at rest with the platform-wide AES key.
type Client struct {
	db     *pgxpool.Pool
	encKey []byte
}

func NewClient(db *pgxpool.Pool, encKey []byte) *Client {
	return &Client{db: db, encKey: encKey}
}

// tenantCreds loads and decrypts the GitHub App credentials for a tenant.
func (c *Client) tenantCreds(ctx context.Context, tenantID uuid.UUID) (appID int64, pemKey []byte, err error) {
	var encrypted []byte
	err = c.db.QueryRow(ctx, `
		SELECT app_id, private_key_encrypted
		FROM tenant_github_app_configs
		WHERE tenant_id = $1`, tenantID,
	).Scan(&appID, &encrypted)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, ErrNoTenantConfig
		}
		return 0, nil, fmt.Errorf("load tenant config: %w", err)
	}

	pemKey, err = crypto.Decrypt(encrypted, c.encKey)
	if err != nil {
		return 0, nil, fmt.Errorf("decrypt PEM: %w", err)
	}
	return appID, pemKey, nil
}

// VerifyAppCredentials calls GET /app authenticated as the App itself (not as
// an installation) to confirm the App ID + PEM are valid and match. Returns
// nil if the App authenticates and its ID matches the provided appID.
// This does NOT validate any installation — only the App credentials.
func VerifyAppCredentials(ctx context.Context, appID int64, pemKey []byte) error {
	atr, err := ghinstallation.NewAppsTransport(http.DefaultTransport, appID, pemKey)
	if err != nil {
		return fmt.Errorf("create app transport: %w", err)
	}
	gh := gogithub.NewClient(&http.Client{Transport: atr})
	app, _, err := gh.Apps.Get(ctx, "")
	if err != nil {
		return fmt.Errorf("authenticate as app: %w", err)
	}
	if app.GetID() != appID {
		return fmt.Errorf("app ID mismatch: PEM belongs to app %d, not %d", app.GetID(), appID)
	}
	return nil
}

func (c *Client) installationClient(ctx context.Context, tenantID uuid.UUID, installationID int64) (*gogithub.Client, error) {
	appID, pemKey, err := c.tenantCreds(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	itr, err := ghinstallation.New(http.DefaultTransport, appID, installationID, pemKey)
	if err != nil {
		return nil, fmt.Errorf("create installation transport: %w", err)
	}
	return gogithub.NewClient(&http.Client{Transport: itr}), nil
}

// ListOrgReposPage returns a single page of non-archived repositories for the
// org. nextPage is 0 when there are no more pages. Use this for paginated
// browsing; use ListOrgRepos when you need the full set (e.g. full sync).
func (c *Client) ListOrgReposPage(
	ctx context.Context,
	tenantID uuid.UUID,
	installationID int64,
	orgLogin string,
	page, perPage int,
) (repos []*gogithub.Repository, nextPage int, err error) {
	if perPage <= 0 || perPage > 100 {
		perPage = 50
	}
	if page < 1 {
		page = 1
	}

	gh, err := c.installationClient(ctx, tenantID, installationID)
	if err != nil {
		return nil, 0, err
	}

	rawRepos, resp, err := gh.Repositories.ListByOrg(ctx, orgLogin, &gogithub.RepositoryListByOrgOptions{
		Type:        "all",
		ListOptions: gogithub.ListOptions{Page: page, PerPage: perPage},
	})
	if err != nil {
		return nil, 0, classifyTokenError(fmt.Errorf("list repos: %w", err))
	}

	filtered := make([]*gogithub.Repository, 0, len(rawRepos))
	for _, r := range rawRepos {
		if !r.GetArchived() {
			filtered = append(filtered, r)
		}
	}
	return filtered, resp.NextPage, nil
}

// ListOrgRepos returns all non-archived repositories for the given org. It
// walks every page on the GitHub side, so prefer ListOrgReposPage in latency
// sensitive paths.
func (c *Client) ListOrgRepos(ctx context.Context, tenantID uuid.UUID, installationID int64, orgLogin string) ([]*gogithub.Repository, error) {
	var allRepos []*gogithub.Repository
	page := 1
	for {
		repos, next, err := c.ListOrgReposPage(ctx, tenantID, installationID, orgLogin, page, 100)
		if err != nil {
			return nil, err
		}
		allRepos = append(allRepos, repos...)
		if next == 0 {
			break
		}
		page = next
	}
	return allRepos, nil
}

// GetCODEOWNERS fetches the CODEOWNERS file from any of the standard locations.
// Returns empty string when no CODEOWNERS file exists (not an error).
func (c *Client) GetCODEOWNERS(ctx context.Context, tenantID uuid.UUID, installationID int64, owner, repo, branch string) (string, error) {
	gh, err := c.installationClient(ctx, tenantID, installationID)
	if err != nil {
		return "", err
	}

	paths := []string{"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"}
	for _, path := range paths {
		fc, _, resp, err := gh.Repositories.GetContents(ctx, owner, repo, path, &gogithub.RepositoryContentGetOptions{
			Ref: branch,
		})
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				continue
			}
			return "", fmt.Errorf("get %s: %w", path, err)
		}
		content, err := fc.GetContent()
		if err != nil {
			return "", fmt.Errorf("decode %s: %w", path, err)
		}
		return content, nil
	}
	return "", nil
}

// CloneRepo performs a shallow clone (depth=1) of the repository using a
// short-lived installation token. Returns the path to the cloned directory.
func (c *Client) CloneRepo(ctx context.Context, tenantID uuid.UUID, installationID int64, owner, repo, branch, destDir string) (string, error) {
	appID, pemKey, err := c.tenantCreds(ctx, tenantID)
	if err != nil {
		return "", err
	}
	itr, err := ghinstallation.New(http.DefaultTransport, appID, installationID, pemKey)
	if err != nil {
		return "", fmt.Errorf("create transport for token: %w", err)
	}

	token, err := itr.Token(ctx)
	if err != nil {
		token = ""
	}

	cloneURL := fmt.Sprintf("https://x-access-token:%s@github.com/%s/%s.git", token, owner, repo)
	if token == "" {
		cloneURL = fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
	}

	repoDir := filepath.Join(destDir, fmt.Sprintf("%s-%s-%d", owner, repo, time.Now().UnixMilli()))
	if err := os.MkdirAll(repoDir, 0750); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}

	args := []string{"clone", "--depth=1", "--single-branch"}
	if branch != "" {
		args = append(args, "--branch", branch)
	}
	args = append(args, cloneURL, repoDir)

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		masked := strings.ReplaceAll(string(out), token, "***")
		return "", fmt.Errorf("git clone: %w\n%s", err, masked)
	}
	return repoDir, nil
}

// GetDefaultBranch returns the default branch name for a repo.
func (c *Client) GetDefaultBranch(ctx context.Context, tenantID uuid.UUID, installationID int64, owner, repo string) (string, error) {
	gh, err := c.installationClient(ctx, tenantID, installationID)
	if err != nil {
		return "", err
	}
	r, _, err := gh.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return "", fmt.Errorf("get repo: %w", err)
	}
	return r.GetDefaultBranch(), nil
}

type GitHubMember struct {
	ID        int64
	Login     string
	Name      string
	AvatarURL string
}

// ListOrgMembers returns organization members visible to the GitHub App installation.
func (c *Client) ListOrgMembers(
	ctx context.Context,
	tenantID uuid.UUID,
	installationID int64,
	orgLogin string,
) ([]GitHubMember, error) {
	gh, err := c.installationClient(ctx, tenantID, installationID)
	if err != nil {
		return nil, err
	}

	var all []GitHubMember
	opts := &gogithub.ListMembersOptions{ListOptions: gogithub.ListOptions{PerPage: 100}}
	for {
		members, resp, err := gh.Organizations.ListMembers(ctx, orgLogin, opts)
		if err != nil {
			return nil, classifyTokenError(fmt.Errorf("list org members: %w", err))
		}
		for _, m := range members {
			all = append(all, GitHubMember{
				ID:        m.GetID(),
				Login:     m.GetLogin(),
				Name:      m.GetName(),
				AvatarURL: m.GetAvatarURL(),
			})
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

// ListTeamMembers returns members for a team slug in the organization.
func (c *Client) ListTeamMembers(
	ctx context.Context,
	tenantID uuid.UUID,
	installationID int64,
	orgLogin, teamSlug string,
) ([]GitHubMember, error) {
	gh, err := c.installationClient(ctx, tenantID, installationID)
	if err != nil {
		return nil, err
	}

	var all []GitHubMember
	opts := &gogithub.TeamListTeamMembersOptions{ListOptions: gogithub.ListOptions{PerPage: 100}}
	for {
		members, resp, err := gh.Teams.ListTeamMembersBySlug(ctx, orgLogin, teamSlug, opts)
		if err != nil {
			return nil, classifyTokenError(fmt.Errorf("list team members for %s: %w", teamSlug, err))
		}
		for _, m := range members {
			all = append(all, GitHubMember{
				ID:        m.GetID(),
				Login:     m.GetLogin(),
				Name:      m.GetName(),
				AvatarURL: m.GetAvatarURL(),
			})
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}
