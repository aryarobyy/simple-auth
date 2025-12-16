package controller

import (
	"auth/internal/helper"
	"auth/internal/model"
	"auth/internal/service"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

type UserController struct {
	service service.UserService
}

func NewUserController(s service.UserService) *UserController {
	return &UserController{service: s}
}

func (h *UserController) Create(w http.ResponseWriter, r *http.Request) {
	user := model.User{}
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		helper.RespondError(w, http.StatusBadRequest, err)
		return
	}

	res, err := h.service.Create(r.Context(), user)
	if err != nil {
		helper.RespondError(w, http.StatusBadRequest, err)
		return
	}

	helper.RespondSuccess(w, http.StatusCreated, res)
}

func (h *UserController) Login(w http.ResponseWriter, r *http.Request) {
	user := model.User{}
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		helper.RespondError(w, http.StatusBadRequest, err)
		return
	}

	res, token, err := h.service.Login(r.Context(), user)
	if err != nil {
		helper.RespondError(w, http.StatusUnauthorized, err)
		return
	}

	cookie := http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)

	helper.RespondSuccess(w, http.StatusAccepted, res)
}

func (h *UserController) GetById(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, strErr := strconv.Atoi(idStr)
	if strErr != nil {
		helper.RespondError(w, http.StatusBadRequest, strErr)
		return
	}

	res, err := h.service.GetById(r.Context(), id)
	if err != nil {
		helper.RespondError(w, http.StatusBadRequest, err)
		return
	}

	helper.RespondSuccess(w, http.StatusAccepted, res)
}

func (h *UserController) GetByUsername(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	res, err := h.service.GetByUsername(r.Context(), username)
	if err != nil {
		helper.RespondError(w, http.StatusBadRequest, err)
		return
	}

	helper.RespondSuccess(w, http.StatusAccepted, res)
}
