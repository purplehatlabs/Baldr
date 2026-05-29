package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"
	"github.com/purplehatlabs/Baldr/internal/api/middleware"
	"github.com/purplehatlabs/Baldr/internal/api/routes"
	"github.com/purplehatlabs/Baldr/internal/auth"
	"github.com/purplehatlabs/Baldr/internal/config"
	"github.com/purplehatlabs/Baldr/internal/db"
	githubclient "github.com/purplehatlabs/Baldr/internal/github"
	"github.com/purplehatlabs/Baldr/internal/queue"
	"github.com/purplehatlabs/Baldr/internal/scheduler"
	"go.uber.org/zap"
)

func main() {
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()

	cfg := config.Load()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.RunMigrations(cfg.DatabaseURL, "./internal/db/migrations"); err != nil {
		log.Fatal("run migrations", zap.Error(err))
	}

	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal("connect to database", zap.Error(err))
	}
	defer pool.Close()

	redisOpt, err := asynq.ParseRedisURI(cfg.RedisURL)
	if err != nil {
		log.Fatal("parse redis URI", zap.Error(err))
	}

	sched, err := scheduler.New(redisOpt, pool, log, cfg.GitHubMembershipSyncEnabled)
	if err != nil {
		log.Fatal("create scheduler", zap.Error(err))
	}

	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()
	sched.Start(bgCtx)
	defer sched.Stop()

	tokens := auth.NewTokenService(cfg.JWTSecret)

	var googleProvider *auth.GoogleProvider
	if cfg.GoogleSSOEnabled && cfg.GoogleClientID != "" {
		googleProvider = auth.NewGoogleProvider(cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.GoogleRedirectURL)
	}
	var githubProvider *auth.GitHubProvider
	if cfg.GitHubSSOEnabled && cfg.GitHubClientID != "" {
		githubProvider = auth.NewGitHubProvider(cfg.GitHubClientID, cfg.GitHubClientSecret, cfg.GitHubRedirectURL)
	}

	authMW := middleware.Auth(tokens)

	r := gin.New()
	if cfg.DevAuthEnabled {
		log.Warn("DEV_AUTH_ENABLED=true — login sem SSO ativo (nunca use em produção)")
	}
	r.Use(gin.Recovery())
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{cfg.FrontendBaseURL},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "Accept-Language"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	routes.RegisterHealth(r)

	authHandler := routes.NewAuthHandler(routes.AuthHandlerConfig{
		Google:          googleProvider,
		GitHub:          githubProvider,
		Tokens:          tokens,
		DB:              pool,
		Log:             log,
		FrontendBaseURL: cfg.FrontendBaseURL,
		GoogleEnabled:   cfg.GoogleSSOEnabled,
		GitHubEnabled:   cfg.GitHubSSOEnabled,
	})
	authHandler.Register(r)
	authHandler.RegisterProtected(r, authMW)

	if cfg.DevAuthEnabled {
		routes.NewDevAuthHandler(tokens, pool, log).Register(r)
	}

	ghClient := githubclient.NewClient(pool, cfg.PEMEncryptionKey)
	asynqClient := asynq.NewClient(redisOpt)
	defer func() { _ = asynqClient.Close() }()
	enqueuer := queue.NewEnqueuer(asynqClient)

	routes.NewOrgsHandler(pool, ghClient, sched, enqueuer, cfg.GitHubMembershipSyncEnabled, log).Register(r, authMW)
	routes.NewReposHandler(pool, sched, log).Register(r, authMW)
	routes.NewScanJobsHandler(pool, log).Register(r, authMW)
	routes.NewSupplyChainSignalsHandler(pool, log).Register(r, authMW)
	routes.NewFindingsHandler(pool, enqueuer, cfg, ghClient, log).Register(r, authMW)
	routes.NewPoliciesHandler(pool, log).Register(r, authMW)
	routes.NewExceptionsHandler(pool, log).Register(r, authMW)
	routes.NewIntegrationsHandler(pool, log).Register(r, authMW)
	routes.NewTeamsHandler(pool, log).Register(r, authMW)
	routes.NewDashboardHandler(pool, log).Register(r, authMW)
	routes.NewMetricsHandler(pool, log).Register(r, authMW)
	routes.NewProjectsHandler(pool, log).Register(r, authMW)
	routes.NewSettingsHandler(pool, cfg.PEMEncryptionKey, log).Register(r, authMW)
	routes.NewWebhookHandler(pool, sched, cfg.GitHubWebhookSecret, log).Register(r)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%s", cfg.APIPort),
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Info("API server starting", zap.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("listen", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatal("server forced to shutdown", zap.Error(err))
	}
	log.Info("server exited")
}
