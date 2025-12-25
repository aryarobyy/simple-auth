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

	helper.RespondSuccess(w, http.StatusCreated, res)
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

	cookie := http.Cookie{
		Name:     "token",
		Value:    refreshToken,
		Path:     "/",
		MaxAge:   3600 * 24 * 7,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)

	helper.RespondSuccessWithToken(w, http.StatusAccepted, res, token)
}

func (h *AuthController) RefreshToken(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		helper.RespondError(w, http.StatusUnauthorized, err)
		return
	}

	refreshToken := cookie.Value

	s := h.service.Auth()
	newToken, tokenErr := s.RefreshToken(r.Context(), refreshToken)
	if tokenErr != nil {
		helper.RespondError(w, http.StatusUnauthorized, err)
		return
	}

	helper.RespondSuccessWithToken(w, http.StatusAccepted, nil, newToken)
}
