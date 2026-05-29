package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type GitHubUserInfo struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

type GitHubProvider struct {
	config *oauth2.Config
}

func NewGitHubProvider(clientID, clientSecret, redirectURL string) *GitHubProvider {
	return &GitHubProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"read:user", "user:email"},
			Endpoint:     github.Endpoint,
		},
	}
}

func (g *GitHubProvider) AuthURL(state string) string {
	return g.config.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

func (g *GitHubProvider) Exchange(ctx context.Context, code string) (*GitHubUserInfo, error) {
	token, err := g.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}

	client := g.config.Client(ctx, token)

	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, fmt.Errorf("fetch user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user endpoint returned status %d", resp.StatusCode)
	}

	var info GitHubUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode user: %w", err)
	}

	if info.Email == "" {
		email, err := g.fetchPrimaryEmail(ctx, client)
		if err != nil {
			return nil, err
		}
		info.Email = email
	}

	if info.Name == "" {
		info.Name = info.Login
	}

	return &info, nil
}

func (g *GitHubProvider) fetchPrimaryEmail(ctx context.Context, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", fmt.Errorf("build emails request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch emails: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("emails endpoint returned status %d", resp.StatusCode)
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", fmt.Errorf("decode emails: %w", err)
	}

	for _, item := range emails {
		if item.Primary && item.Verified {
			return item.Email, nil
		}
	}
	for _, item := range emails {
		if item.Verified {
			return item.Email, nil
		}
	}
	for _, item := range emails {
		if item.Email != "" {
			return item.Email, nil
		}
	}

	return "", fmt.Errorf("no email available from GitHub profile")
}

func GitHubUserIDString(id int64) string {
	return strconv.FormatInt(id, 10)
}
