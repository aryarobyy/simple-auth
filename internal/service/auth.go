package service

import (
	"context"
	"fmt"

	"auth/internal/helper"
	"auth/internal/model"
	"auth/internal/repository"

	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	Create(ctx context.Context, user model.User) (*model.User, error)
	Login(ctx context.Context, user model.User) (*model.User, string, string, error)
	RefreshToken(ctx context.Context, refreshToken string) (string, error)
}

type authService struct {
	repo        repository.AuthRepo
	userRepo    repository.UserRepo
	redisClient *redis.Client
}

func NewAuthService(
	repo repository.AuthRepo,
	userRepo repository.UserRepo,
	redisClient *redis.Client,
) AuthService {
	return &authService{
		repo:        repo,
		userRepo:    userRepo,
		redisClient: redisClient,
	}
}

func (h *authService) Create(ctx context.Context, user model.User) (*model.User, error) {
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

func (h *authService) Login(ctx context.Context, user model.User) (*model.User, string, string, error) {
	res, err := h.userRepo.GetByUsername(ctx, user.Username)
	if err != nil {
		return nil, "", "", fmt.Errorf("user not found", err)
	}

	passErr := bcrypt.CompareHashAndPassword([]byte(res.Password), []byte(user.Password))
	if passErr != nil {
		return nil, "", "", fmt.Errorf("wrong password")
	}

	refreshToken, err := helper.CreateRefreshToken(ctx, user, h.redisClient)
	if err != nil {
		return nil, "", "", fmt.Errorf("user not found", err)
	}

	token, err := helper.CreateAccessToken(*res)
	if err != nil {
		return nil, "", "", fmt.Errorf("user not found", err)
	}
	return res, refreshToken, token, nil
}

// generate new token here
func (h *authService) RefreshToken(
	ctx context.Context,
	refreshToken string,
) (string, error) {
	refreshClaims, err := helper.ValidateRefreshToken(
		ctx,
		refreshToken,
		h.redisClient,
	)
	if err != nil {
		return "", err
	}

	user := model.User{
		ID:       refreshClaims.UserId,
		Username: refreshClaims.Username,
		Role:     model.Role(refreshClaims.Role),
	}

	newAccessToken, err := helper.CreateAccessToken(user)
	if err != nil {
		return "", err
	}

	return newAccessToken, nil
}
