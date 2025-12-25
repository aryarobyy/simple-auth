package controller

import (
	"net/http"
	"strconv"

	"auth/internal/helper"
	"auth/internal/service"

	"github.com/go-chi/chi/v5"
)

type UserController struct {
	service service.Service
}

func NewUserController(s service.Service) *UserController {
	return &UserController{service: s}
}

func (h *UserController) GetById(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, strErr := strconv.Atoi(idStr)
	if strErr != nil {
		helper.RespondError(w, http.StatusBadRequest, strErr)
		return
	}

	s := h.service.User()
	res, err := s.GetById(r.Context(), id)
	if err != nil {
		helper.RespondError(w, http.StatusBadRequest, err)
		return
	}

	helper.RespondSuccess(w, http.StatusAccepted, res)
}

func (h *UserController) GetByUsername(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	s := h.service.User()
	res, err := s.GetByUsername(r.Context(), username)
	if err != nil {
		helper.RespondError(w, http.StatusBadRequest, err)
		return
	}

	helper.RespondSuccess(w, http.StatusAccepted, res)
}

func (h *UserController) GetMany(w http.ResponseWriter, r *http.Request) {
	limit, offset, pagErr := helper.Pagination(r)
	if pagErr != nil {
		helper.RespondError(w, http.StatusBadRequest, pagErr)
		return
	}

	s := h.service.User()
	res, err := s.GetMany(r.Context(), limit, offset)
	if err != nil {
		helper.RespondError(w, http.StatusBadRequest, pagErr)
		return
	}

	helper.RespondSuccess(w, http.StatusAccepted, res)
}
