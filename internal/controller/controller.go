package controller

import (
	"auth/internal/service"
)

type Controller interface {
	User() UserController
	Auth() AuthController
}
type controller struct {
	srv service.Service
}

func NewController(
	srv service.Service,
) *controller {
	return &controller{srv: srv}
}

func (c *controller) Auth() AuthController {
	return AuthController{service: c.srv}
}

func (c *controller) User() UserController {
	return UserController{service: c.srv}
}
