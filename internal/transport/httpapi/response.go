package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/harshal5-dev/auth-service/internal/domain"
)

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ErrorEnvelope struct {
	Error ErrorBody `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, ErrorEnvelope{
		Error: ErrorBody{
			Code:    code,
			Message: message,
		},
	})
}

func handleDomainError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error) {

	switch {
	case errors.Is(err, domain.ErrEmailAlreadyExists):
		writeError(w, http.StatusConflict, "EMAIL_ALREADY_EXISTS", "An account with this email already exists.")
	case errors.Is(err, domain.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password.")
	case errors.Is(err, domain.ErrInvalidRefreshToken):
		writeError(w, http.StatusUnauthorized, "INVALID_REFRESH_TOKEN", "Session expired or invalid. Please log in again.")
	case errors.Is(err, domain.ErrAccountDisabled):
		writeError(w, http.StatusForbidden, "ACCOUNT_DISABLED", "This user account has been disabled.")
	default:
		logger.ErrorContext(r.Context(), "unhandled internal error", "path", r.URL.Path, "err", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected internal error occurred.")
	}
}
