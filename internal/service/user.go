package service

import (
	"context"
	"fmt"

	"auth/internal/model"
	"auth/internal/repository"
)

type UserService interface {
	GetById(ctx context.Context, id int) (*model.User, error)
	GetByUsername(ctx context.Context, username string) (*model.User, error)
	GetMany(ctx context.Context, limit int, offset int) ([]model.User, error)
}

type userService struct {
	repo repository.Repository
}

func NewUserService(repo repository.Repository) UserService {
	return &userService{repo: repo}
}

func (h *userService) GetById(ctx context.Context, id int) (*model.User, error) {
	r := h.repo.User()
	res, err := r.GetById(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed getting user: %w", err)
	}
	return res, nil
}

func (h *userService) GetByUsername(ctx context.Context, username string) (*model.User, error) {
	r := h.repo.User()
	res, err := r.GetByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("failed getting user: %w", err)
	}
	return res, nil
}

func (h *userService) GetMany(ctx context.Context, limit int, offset int) ([]model.User, error) {
	r := h.repo.User()
	res, err := r.GetMany(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed getting users: %w", err)
	}
	return res, nil
}
