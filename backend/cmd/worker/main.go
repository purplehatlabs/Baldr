package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hibiken/asynq"
	"github.com/purplehatlabs/Baldr/internal/config"
	"github.com/purplehatlabs/Baldr/internal/db"
	githubclient "github.com/purplehatlabs/Baldr/internal/github"
	"github.com/purplehatlabs/Baldr/internal/queue"
	"go.uber.org/zap"
)

func main() {
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()

	cfg := config.Load()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal("connect to database", zap.Error(err))
	}
	defer pool.Close()

	redisOpt, err := asynq.ParseRedisURI(cfg.RedisURL)
	if err != nil {
		log.Fatal("parse redis URI", zap.Error(err))
	}

	ghClient := githubclient.NewClient(pool, cfg.PEMEncryptionKey)
	asynqClient := asynq.NewClient(redisOpt)
	defer func() { _ = asynqClient.Close() }()
	enqueuer := queue.NewEnqueuer(asynqClient)

	srv := asynq.NewServer(redisOpt, asynq.Config{
		Concurrency: cfg.WorkerConcurrency,
		Queues: map[string]int{
			queue.QueueScan:     10,
			queue.QueueAnalysis: 5,
			queue.QueueDefault:  1,
		},
	})

	mux := asynq.NewServeMux()
	queue.RegisterHandlers(mux, pool, ghClient, cfg, enqueuer, log)

	log.Info("worker starting", zap.Int("concurrency", cfg.WorkerConcurrency))

	go func() {
		if err := srv.Run(mux); err != nil {
			log.Fatal("run worker", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("worker shutting down...")
	srv.Shutdown()
}
