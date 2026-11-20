package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/harshal5-dev/auth-service/internal/config"
	"github.com/harshal5-dev/auth-service/internal/repository/postgres"
	"github.com/harshal5-dev/auth-service/internal/security"
	"github.com/harshal5-dev/auth-service/internal/service"
	"github.com/harshal5-dev/auth-service/internal/transport/httpapi"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
)

type infraPinger struct {
	pgPool      *pgxpool.Pool
	redisClient *goredis.Client
}

func (p *infraPinger) PingPostgres(ctx context.Context) error {
	return p.pgPool.Ping(ctx)
}

func (p *infraPinger) PingRedis(ctx context.Context) error {
	return p.redisClient.Ping(ctx).Err()
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load configuration", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pgConfig, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		logger.Error("invalid DATABASE_URL", "err", err)
		os.Exit(1)
	}
	pgConfig.MaxConns = cfg.DBMaxConns
	pgConfig.MinConns = cfg.DBMinConns

	pgPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		logger.Error("failed to create postgres pool", "err", err)
		os.Exit(1)
	}
	defer pgPool.Close()

	if err := pgPool.Ping(ctx); err != nil {
		logger.Error("failed to ping postgres at startup", "err", err)
		os.Exit(1)
	}
	logger.Info("connected to PostgreSQL 16")

	redisClient := goredis.NewClient(&goredis.Options{
		Addr: cfg.RedisAddr,
		DB:   cfg.RedisDB,
	})
	defer func() { _ = redisClient.Close() }()

	if err := redisClient.Ping(ctx).Err(); err != nil {
		logger.Error("failed to ping redis at startup", "err", err)
		os.Exit(1)
	}
	logger.Info("connected to Redis 8")

	hasher, err := security.NewPasswordHasher(security.Argon2Params{
		MemoryKiB:   cfg.Argon2MemoryKiB,
		Iterations:  cfg.Argon2Iterations,
		Parallelism: cfg.Argon2Parallelism,
	})
	if err != nil {
		logger.Error("failed to initialize Argon2id password hasher", "err", err)
		os.Exit(1)
	}

	jwtManager, err := security.NewJWTManager(
		cfg.PrivateKey,
		cfg.PublicKey,
		cfg.Ed25519KeyID,
		cfg.JWTIssuer,
		cfg.AccessTokenTTL,
	)
	if err != nil {
		logger.Error("failed to initialize Ed25519 JWT manager", "err", err)
		os.Exit(1)
	}

	userRepo := postgres.NewUserRepository(pgPool)
	authService := service.NewAuthService(userRepo, hasher, jwtManager, logger)

	pinger := &infraPinger{pgPool: pgPool, redisClient: redisClient}
	handler := httpapi.NewHandler(authService, pinger, logger)
	router := httpapi.NewRouter(handler, logger)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:      router,
		ReadTimeout:  cfg.HTTPReadTimeout,
		WriteTimeout: cfg.HTTPWriteTimeout,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Info("starting auth-service HTTP server", "port", cfg.HTTPPort, "env", cfg.AppEnv)

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server crashed", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("shutdown signal received; draining in-flight HTTP requests...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful HTTP shutdown failed", "err", err)
	}
	logger.Info("auth-service stopped cleanly")
}
