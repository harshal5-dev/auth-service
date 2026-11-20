package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/harshal5-dev/auth-service/internal/domain"
	"github.com/harshal5-dev/auth-service/internal/service"
)

const maxRequestBodyBytes = 1 << 20

type ReadinessChecker interface {
	PingPostgres(ctx context.Context) error
	PingRedis(ctx context.Context) error
}

type Handler struct {
	authService *service.AuthService
	readiness   ReadinessChecker
	logger      *slog.Logger
}

func NewHandler(
	authService *service.AuthService,
	readiness ReadinessChecker,
	logger *slog.Logger,
) *Handler {
	return &Handler{
		authService: authService,
		readiness:   readiness,
		logger:      logger,
	}
}

func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Malformed JSON request body.")
		return
	}

	if err := req.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	user, err := h.authService.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		handleDomainError(w, r, h.logger, err)
		return
	}

	writeJSON(w, http.StatusCreated, RegisterResponse{
		User: toUserDTO(user),
	})
}

func (h *Handler) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) HandleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := h.readiness.PingPostgres(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "POSTGRES_UNAVAILABLE", "Database is not ready.")
		return
	}

	if err := h.readiness.PingRedis(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "REDIS_UNAVAILABLE", "Redis cache is not ready.")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":   "ready",
		"postgres": "up",
		"redis":    "up",
	})
}

func toUserDTO(u *domain.User) UserDTO {
	return UserDTO{
		ID:        u.ID,
		Email:     u.Email,
		Roles:     u.Roles,
		CreatedAt: u.CreatedAt,
	}
}
