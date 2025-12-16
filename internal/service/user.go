package service

import (
	"auth/internal/helper"
	"auth/internal/model"
	"auth/internal/repository"
	"context"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

type UserService interface {
	Create(ctx context.Context, user model.User) (*model.User, error)
	GetById(ctx context.Context, id int) (*model.User, error)
	GetByUsername(ctx context.Context, username string) (*model.User, error)
	Login(ctx context.Context, user model.User) (*model.User, string, error)
}

type userService struct {
	repo repository.UserRepo
}

func NewUserService(repo repository.UserRepo) UserService {
	return &userService{repo: repo}
}

func (h *userService) Create(ctx context.Context, user model.User) (*model.User, error) {
	if user.Username == "" && user.Password == "" {
		return nil, fmt.Errorf("Username or password cannot be nul")
	}

	if !helper.IsValidName(user.Name) {
		return nil, fmt.Errorf("Name cannot contain name")
	}

	password := user.Password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hashing password", err)
	}

	registerData := model.User{
		Name:     user.Name,
		Password: string(hashedPassword),
		Username: user.Username,
	}

	res, err := h.repo.Create(ctx, registerData)
	if err != nil {
		return nil, fmt.Errorf("failed create user: %w", err)
	}
	return res, nil
}

func (h *userService) Login(ctx context.Context, user model.User) (*model.User, string, error) {
	res, err := h.GetByUsername(ctx, user.Username)
	if err != nil {
		return nil, "", fmt.Errorf("user not found", err)
	}

	comparedPassword := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(res.Password))
	if comparedPassword != nil {
		return nil, "", fmt.Errorf("wrong password", err)
	}

	token, err := helper.CreateToken(user)
	if err != nil {
		return nil, "", fmt.Errorf("user not found", err)
	}
	return res, token, nil
}

func (h *userService) GetById(ctx context.Context, id int) (*model.User, error) {
	res, err := h.repo.GetById(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed getting user: %w", err)
	}
	return res, nil
}

func (h *userService) GetByUsername(ctx context.Context, username string) (*model.User, error) {
	res, err := h.repo.GetByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("failed getting user: %w", err)
	}
	return res, nil
}
