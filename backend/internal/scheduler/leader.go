package scheduler

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	leaderKey       = "baldr:scheduler:leader"
	leaderTTL       = 30 * time.Second
	leaderRenewEvery = 10 * time.Second
)

// LeaderElector ensures only one API replica runs the org scheduler.
type LeaderElector struct {
	client     *redis.Client
	instanceID string
	log        *zap.Logger
}

func NewLeaderElector(redisURL string, log *zap.Logger) (*LeaderElector, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	return &LeaderElector{
		client:     redis.NewClient(opts),
		instanceID: uuid.NewString(),
		log:        log,
	}, nil
}

func (l *LeaderElector) Close() error {
	return l.client.Close()
}

// Run acquires the leader lock, invokes onLead while leader, and releases on shutdown.
func (l *LeaderElector) Run(ctx context.Context, onLead func(context.Context)) {
	ticker := time.NewTicker(leaderRenewEvery)
	defer ticker.Stop()

	for {
		acquired, err := l.tryAcquire(ctx)
		if err != nil {
			l.log.Warn("scheduler leader election error", zap.Error(err))
		}
		if acquired {
			l.log.Info("scheduler leader acquired", zap.String("instance_id", l.instanceID))
			leadCtx, cancel := context.WithCancel(ctx)
			go onLead(leadCtx)

			for {
				select {
				case <-ctx.Done():
					cancel()
					_ = l.release(context.Background())
					return
				case <-ticker.C:
					if err := l.renew(ctx); err != nil {
						l.log.Warn("scheduler leader renew failed", zap.Error(err))
						cancel()
						return
					}
				}
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(leaderRenewEvery):
		}
	}
}

func (l *LeaderElector) tryAcquire(ctx context.Context) (bool, error) {
	ok, err := l.client.SetNX(ctx, leaderKey, l.instanceID, leaderTTL).Result()
	if err != nil {
		return false, err
	}
	return ok, nil
}

func (l *LeaderElector) renew(ctx context.Context) error {
	script := redis.NewScript(`
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			return redis.call("PEXPIRE", KEYS[1], ARGV[2])
		end
		return 0
	`)
	result, err := script.Run(ctx, l.client, []string{leaderKey}, l.instanceID, leaderTTL.Milliseconds()).Int64()
	if err != nil {
		return err
	}
	if result == 0 {
		return fmt.Errorf("lost scheduler leadership")
	}
	return nil
}

func (l *LeaderElector) release(ctx context.Context) error {
	script := redis.NewScript(`
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			return redis.call("DEL", KEYS[1])
		end
		return 0
	`)
	_, err := script.Run(ctx, l.client, []string{leaderKey}, l.instanceID).Result()
	return err
}
