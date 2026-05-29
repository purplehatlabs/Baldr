package config

import (
	"log"
	"os"
	"strings"

	"github.com/purplehatlabs/Baldr/internal/crypto"
	"github.com/spf13/viper"
)

type Config struct {
	APIPort         string
	APIBaseURL      string
	FrontendBaseURL string
	DatabaseURL     string
	RedisURL        string

	JWTSecret string

	DevAuthEnabled bool

	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string
	GoogleSSOEnabled   bool

	GitHubClientID              string
	GitHubClientSecret          string
	GitHubRedirectURL           string
	GitHubSSOEnabled            bool
	GitHubMembershipSyncEnabled bool
	GitHubWebhookSecret         string

	// PEMEncryptionKey is the 32-byte AES-256 key used to encrypt tenant
	// GitHub App private keys at rest. Loaded from PEM_ENCRYPTION_KEY (base64).
	PEMEncryptionKey []byte

	WorkerConcurrency int
	GuardDogEnabled   bool
	GuardDogBinary    string
	GuardDogTimeoutS  int

	LiteLLMBaseURL        string
	LiteLLMAPIKey         string
	LiteLLMModel          string
	LiteLLMTimeoutSeconds int

	PackageDynamicAnalysisEnabled        bool
	PackageDynamicAnalysisEndpointURL    string
	PackageDynamicAnalysisTimeoutSeconds int

	MaliciousDatasetEnabled        bool
	MaliciousDatasetURL            string
	MaliciousDatasetTimeoutSeconds int
}

func Load() *Config {
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	viper.SetDefault("API_PORT", "8080")
	viper.SetDefault("API_BASE_URL", "http://localhost:8080")
	viper.SetDefault("FRONTEND_BASE_URL", "http://localhost:3000")
	viper.SetDefault("REDIS_URL", "redis://localhost:6379")
	viper.SetDefault("WORKER_CONCURRENCY", 3)
	viper.SetDefault("GUARDDOG_ENABLED", false)
	viper.SetDefault("GUARDDOG_BINARY", "guarddog")
	viper.SetDefault("GUARDDOG_TIMEOUT_SECONDS", 120)
	viper.SetDefault("LITELLM_BASE_URL", "http://localhost:4000")
	viper.SetDefault("LITELLM_MODEL", "gpt-4o-mini")
	viper.SetDefault("LITELLM_TIMEOUT_SECONDS", 60)
	viper.SetDefault("MALICIOUS_DATASET_URL", "https://codeload.github.com/ossf/malicious-packages/zip/refs/heads/main")
	viper.SetDefault("MALICIOUS_DATASET_TIMEOUT_SECONDS", 120)
	viper.SetDefault("MALICIOUS_DATASET_ENABLED", true)
	viper.SetDefault("PACKAGE_DYNAMIC_ANALYSIS_ENABLED", false)
	viper.SetDefault("PACKAGE_DYNAMIC_ANALYSIS_TIMEOUT_SECONDS", 20)
	viper.SetDefault("GITHUB_SSO_ENABLED", true)
	viper.SetDefault("GOOGLE_SSO_ENABLED", true)
	viper.SetDefault("GITHUB_MEMBERSHIP_SYNC_ENABLED", true)

	// Load .env file if present (dev convenience)
	if _, err := os.Stat(".env"); err == nil {
		viper.SetConfigFile(".env")
		viper.SetConfigType("env")
		if err := viper.ReadInConfig(); err != nil {
			log.Printf("warn: could not read .env: %v", err)
		}
	}

	devAuth := viper.GetBool("DEV_AUTH_ENABLED")

	cfg := &Config{
		APIPort:         viper.GetString("API_PORT"),
		APIBaseURL:      viper.GetString("API_BASE_URL"),
		FrontendBaseURL: viper.GetString("FRONTEND_BASE_URL"),
		DatabaseURL:     mustGet("DATABASE_URL"),
		RedisURL:        viper.GetString("REDIS_URL"),

		JWTSecret: mustGet("JWT_SECRET"),

		DevAuthEnabled: devAuth,

		GitHubWebhookSecret:         viper.GetString("GITHUB_WEBHOOK_SECRET"),
		GitHubSSOEnabled:            viper.GetBool("GITHUB_SSO_ENABLED"),
		GoogleSSOEnabled:            viper.GetBool("GOOGLE_SSO_ENABLED"),
		GitHubMembershipSyncEnabled: viper.GetBool("GITHUB_MEMBERSHIP_SYNC_ENABLED"),

		WorkerConcurrency: viper.GetInt("WORKER_CONCURRENCY"),
		GuardDogEnabled:   viper.GetBool("GUARDDOG_ENABLED"),
		GuardDogBinary:    viper.GetString("GUARDDOG_BINARY"),
		GuardDogTimeoutS:  viper.GetInt("GUARDDOG_TIMEOUT_SECONDS"),

		LiteLLMBaseURL:        viper.GetString("LITELLM_BASE_URL"),
		LiteLLMAPIKey:         viper.GetString("LITELLM_API_KEY"),
		LiteLLMModel:          viper.GetString("LITELLM_MODEL"),
		LiteLLMTimeoutSeconds: viper.GetInt("LITELLM_TIMEOUT_SECONDS"),

		PackageDynamicAnalysisEnabled:        viper.GetBool("PACKAGE_DYNAMIC_ANALYSIS_ENABLED"),
		PackageDynamicAnalysisEndpointURL:    viper.GetString("PACKAGE_DYNAMIC_ANALYSIS_ENDPOINT_URL"),
		PackageDynamicAnalysisTimeoutSeconds: viper.GetInt("PACKAGE_DYNAMIC_ANALYSIS_TIMEOUT_SECONDS"),
		MaliciousDatasetEnabled:              viper.GetBool("MALICIOUS_DATASET_ENABLED"),
		MaliciousDatasetURL:                  viper.GetString("MALICIOUS_DATASET_URL"),
		MaliciousDatasetTimeoutSeconds:       viper.GetInt("MALICIOUS_DATASET_TIMEOUT_SECONDS"),
	}

	if cfg.WorkerConcurrency < 1 {
		cfg.WorkerConcurrency = 3
	}
	if cfg.GuardDogTimeoutS < 1 {
		cfg.GuardDogTimeoutS = 120
	}
	if cfg.PackageDynamicAnalysisTimeoutSeconds < 1 {
		cfg.PackageDynamicAnalysisTimeoutSeconds = 20
	}
	if cfg.MaliciousDatasetTimeoutSeconds < 10 {
		cfg.MaliciousDatasetTimeoutSeconds = 120
	}

	encKey, err := crypto.DecodeKey(mustGet("PEM_ENCRYPTION_KEY"))
	if err != nil {
		log.Fatalf("invalid PEM_ENCRYPTION_KEY: %v (generate with: openssl rand -base64 32)", err)
	}
	cfg.PEMEncryptionKey = encKey

	cfg.GoogleClientID = viper.GetString("GOOGLE_CLIENT_ID")
	cfg.GoogleClientSecret = viper.GetString("GOOGLE_CLIENT_SECRET")
	cfg.GoogleRedirectURL = viper.GetString("GOOGLE_REDIRECT_URL")

	cfg.GitHubClientID = viper.GetString("GITHUB_CLIENT_ID")
	cfg.GitHubClientSecret = viper.GetString("GITHUB_CLIENT_SECRET")
	cfg.GitHubRedirectURL = viper.GetString("GITHUB_REDIRECT_URL")

	if !devAuth {
		if cfg.GitHubSSOEnabled {
			cfg.GitHubClientID = mustGet("GITHUB_CLIENT_ID")
			cfg.GitHubClientSecret = mustGet("GITHUB_CLIENT_SECRET")
			cfg.GitHubRedirectURL = mustGet("GITHUB_REDIRECT_URL")
		}
		if cfg.GoogleSSOEnabled {
			cfg.GoogleClientID = mustGet("GOOGLE_CLIENT_ID")
			cfg.GoogleClientSecret = mustGet("GOOGLE_CLIENT_SECRET")
			cfg.GoogleRedirectURL = mustGet("GOOGLE_REDIRECT_URL")
		}
		if !cfg.GitHubSSOEnabled && !cfg.GoogleSSOEnabled {
			log.Fatalf("at least one SSO provider must be enabled (GITHUB_SSO_ENABLED or GOOGLE_SSO_ENABLED)")
		}
	}

	return cfg
}

func mustGet(key string) string {
	v := viper.GetString(key)
	if v == "" {
		log.Fatalf("required env var %s is not set", key)
	}
	return v
}
