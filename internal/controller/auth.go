package controller

import (
	"encoding/json"
	"net/http"

	"auth/internal/helper"
	"auth/internal/model"
	"auth/internal/service"
)

type AuthController struct {
	service service.Service
}

func NewAuthController(s service.Service) *AuthController {
	return &AuthController{service: s}
}

func (h *AuthController) Register(w http.ResponseWriter, r *http.Request) {
	user := model.User{}
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		helper.RespondError(w, http.StatusBadRequest, err)
		return
	}

	s := h.service.Auth()
	res, err := s.Create(r.Context(), user)
	if err != nil {
		helper.RespondError(w, http.StatusBadRequest, err)
		return
	}

	helper.RespondSuccess(w, http.StatusCreated, res, nil, nil)
}

func (h *AuthController) Login(w http.ResponseWriter, r *http.Request) {
	user := model.User{}
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		helper.RespondError(w, http.StatusBadRequest, err)
		return
	}

	s := h.service.Auth()
	res, refreshToken, token, err := s.Login(r.Context(), user)
	if err != nil {
		helper.RespondError(w, http.StatusUnauthorized, err)
		return
	}

	helper.RespondSuccess(w, http.StatusAccepted, res, &token, &refreshToken)
}

func (h *AuthController) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var refreshToken string

	if err := json.NewDecoder(r.Body).Decode(refreshToken); err != nil {
		helper.RespondError(w, http.StatusBadRequest, err)
		return
	}

	s := h.service.Auth()
	newToken, tokenErr := s.RefreshToken(r.Context(), refreshToken)
	if tokenErr != nil {
		helper.RespondError(w, http.StatusUnauthorized, tokenErr)
		return
	}

	helper.RespondSuccess(w, http.StatusAccepted, nil, &newToken, nil)
}
