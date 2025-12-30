package controller

import (
	"encoding/json"
	"errors"
	"fmt"
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

	helper.RespondSuccess(w, http.StatusCreated, res, nil)
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
		Name:     "refresh_token",
		Value:    refreshToken,
		MaxAge:   3600 * 24 * 7,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)
	helper.RespondSuccess(w, http.StatusOK, res, &token)
}

func (h *AuthController) RefreshToken(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			helper.RespondError(w, http.StatusBadRequest, err)
			return
		default:
			helper.RespondError(w, http.StatusInternalServerError, err)
		}
	}
	fmt.Println(cookie.Value)

	s := h.service.Auth()
	newRefreshToken, newAccessToken, tokenErr := s.RefreshToken(r.Context(), cookie.Value)
	if tokenErr != nil {
		helper.RespondError(w, http.StatusUnauthorized, tokenErr)
		return
	}
	newCookie := http.Cookie{
		Name:     "refresh_token",
		Value:    newRefreshToken,
		MaxAge:   3600 * 24 * 7,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &newCookie)

	helper.RespondSuccess(w, http.StatusAccepted, nil, &newAccessToken)
}

func (h *AuthController) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			helper.RespondError(w, http.StatusBadRequest, err)
			return
		default:
			helper.RespondError(w, http.StatusInternalServerError, err)
			return
		}
	}

	s := h.service.Auth()
	if err := s.Logout(r.Context(), cookie.Value); err != nil {
		helper.RespondError(w, http.StatusBadRequest, err)
		return
	}
	helper.RespondSuccess(w, http.StatusOK, nil, nil)
}
