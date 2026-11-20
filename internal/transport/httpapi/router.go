package httpapi

import (
	"log/slog"
	"net/http"
)

func NewRouter(h *Handler, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", h.HandleHealthz)
	mux.HandleFunc("GET /readyz", h.HandleReadyz)

	mux.HandleFunc("POST /api/v1/auth/register", h.HandleRegister)

	var handler http.Handler = mux
	handler = RecoveryMiddleware(logger, handler)
	handler = LoggingMiddleware(logger, handler)
	handler = RequestIDMiddleware(handler)

	return handler
}
