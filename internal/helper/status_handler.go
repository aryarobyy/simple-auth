package helper

import (
	"encoding/json"
	"errors"
	"net/http"
)

type SuccessResponse struct {
	Data    any     `json:"data"`
	Status  int     `json:"status"`
	Token   *string `json:"token,omitempty"`
	Message string  `json:"message"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Status  int    `json:"status"`
	Message string `json:"message"`
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
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(SuccessResponse{
		Status:  status,
		Message: "success",
		Data:    data,
		Token:   token,
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
			Error:   appErr.Message,
			Message: "error",
			Code:    appErr.Code,
		})
		return
	}

	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(ErrorResponse{
		Status:  status,
		Message: "error",
		Error:   err.Error(),
	})
}
