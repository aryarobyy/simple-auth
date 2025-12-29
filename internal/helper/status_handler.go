package helper

import (
	"encoding/json"
	"errors"
	"net/http"
)

type SuccessResponse struct {
	Data         any     `json:"data"`
	Status       int     `json:"status"`
	Token        *string `json:"token,omitempty"`
	RefreshToken *string `json:"refresh_token,omitempty"`
}

type ErrorResponse struct {
	Error  string `json:"error"`
	Code   string `json:"code,omitempty"`
	Status int    `json:"status"`
}

type AppError struct {
	Code    string
	Message string
	Status  int
}

func RespondSuccess(
	w http.ResponseWriter,
	status int,
	data any,
	token *string,
	refreshToken *string,
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(SuccessResponse{
		Status:       status,
		Data:         data,
		Token:        token,
		RefreshToken: refreshToken,
	})
}

func (e *AppError) Error() string {
	return e.Message
}

func RespondError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")

	var appErr *AppError
	if errors.As(err, &appErr) {
		w.WriteHeader(appErr.Status)
		_ = json.NewEncoder(w).Encode(ErrorResponse{
			Error: appErr.Message,
			Code:  appErr.Code,
		})
		return
	}

	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(ErrorResponse{
		Status: status,
		Error:  err.Error(),
	})
}
