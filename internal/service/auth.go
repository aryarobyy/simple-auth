package service

import (
	"context"
	"fmt"
	"time"

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
	repo        repository.Repository
	redisClient *redis.Client
}

func NewAuthService(
	repo repository.Repository,
	redisClient *redis.Client,
) AuthService {
	return &authService{
		repo:        repo,
		redisClient: redisClient,
	}
}

func (h *authService) Create(ctx context.Context, user model.User) (*model.User, error) {
	if user.Username == "" && user.Password == "" {
		return nil, fmt.Errorf("Username or password cannot be nul")
	}
	if user.Role == "" {
		user.Role = "user"
	}

	if !helper.IsValidName(user.Name) {
		return nil, fmt.Errorf("Name cannot contain name")
	}

	password := user.Password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hashing password: %w", err)
	}

	registerData := model.User{
		Name:     user.Name,
		Password: string(hashedPassword),
		Username: user.Username,
	}

	r := h.repo.Auth()
	res, err := r.Create(ctx, registerData)
	if err != nil {
		return nil, fmt.Errorf("failed create user: %w", err)
	}
	return res, nil
}

func (h *authService) Login(ctx context.Context, user model.User) (*model.User, string, string, error) {
	rU := h.repo.User()
	res, err := rU.GetByUsername(ctx, user.Username)
	if err != nil {
		return nil, "", "", fmt.Errorf("user not found: %w", err)
	}

	passErr := bcrypt.CompareHashAndPassword([]byte(res.Password), []byte(user.Password))
	if passErr != nil {
		return nil, "", "", fmt.Errorf("wrong password")
	}

	refreshToken, err := helper.CreateRefreshToken(ctx, user, h.redisClient, &time.Time{})
	if err != nil {
		return nil, "", "", fmt.Errorf("user not found: %w", err)
	}

	token, err := helper.CreateAccessToken(*res)
	if err != nil {
		return nil, "", "", fmt.Errorf("user not found: %w", err)
	}

	return res, refreshToken, token, nil
}

// generate new token here
func (h *authService) RefreshToken(
	ctx context.Context,
	refreshToken string,
) (string, string, error) {
	refreshClaims, err := helper.ValidateRefreshToken(
		ctx,
		refreshToken,
		h.redisClient,
	)
	if err != nil {
		return "", "", err
	}

	user := model.User{
		ID:       refreshClaims.UserID,
		Username: refreshClaims.Username,
		Role:     model.Role(refreshClaims.Role),
	}

	newAccessToken, err := helper.CreateAccessToken(user)
	if err != nil {
		return "", "", err
	}

	newRefreshToken, err := helper.RefreshRotation(ctx, refreshToken, user, h.redisClient)
	if err != nil {
		return "", "", err
	}

	return newAccessToken, newRefreshToken, nil
}

func (h *authService) Logout(
	ctx context.Context,
	refreshToken string,
) error {
	if err := helper.RevokeRefreshToken(ctx, refreshToken, h.redisClient); err != nil {
		return err
	}
	return nil
}
