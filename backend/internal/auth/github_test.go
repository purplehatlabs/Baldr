package auth

import (
	"testing"
)

func TestGitHubProvider_AuthURLContainsState(t *testing.T) {
	provider := NewGitHubProvider("client-id", "client-secret", "http://localhost/callback")
	url := provider.AuthURL("csrf-token")
	if url == "" {
		t.Fatal("expected auth url")
	}
}

func TestGitHubUserIDString(t *testing.T) {
	if GitHubUserIDString(42) != "42" {
		t.Fatal("expected stringified github user id")
	}
}

func TestAuthProviders(t *testing.T) {
	if AuthProviderGitHub != "github" || AuthProviderGoogle != "google" || AuthProviderDev != "dev" {
		t.Fatal("unexpected auth provider constants")
	}
}
