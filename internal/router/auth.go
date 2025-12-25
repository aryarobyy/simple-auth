package router

import (
	"auth/internal/controller"

	"github.com/go-chi/chi/v5"
)

func AuthRoutes(r chi.Router, auth controller.AuthController) {
	r.Post("/", auth.Register)
	r.Post("/login", auth.Login)
	r.Post("/refresh", auth.RefreshToken)
}
