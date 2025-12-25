package router

import (
	"auth/internal/controller"

	"github.com/go-chi/chi/v5"
)

func UserRoutes(r chi.Router, user controller.UserController) {
	// r.Post("/", user.Create)
	// r.Post("/login", user.Login)
	r.Get("/", user.GetMany)
	r.Get("/{id}", user.GetById)
	// r.Put("/{id}", user.Update)
	// r.Delete("/{id}", user.Delete)
}
