package service

import (
	"auth/internal/repository"

	"github.com/redis/go-redis/v9"
)

type Service interface {
	User() userService
	Auth() authService
}
type service struct {
	repo        repository.Repository
	redisClient *redis.Client
}

func NewService(
	repo repository.Repository,
	redisClient *redis.Client,
) *service {
	return &service{
		repo:        repo,
		redisClient: redisClient,
	}
}

func (s *service) Auth() authService {
	return authService{repo: s.repo, redisClient: s.redisClient}
}

func (s *service) User() userService {
	return userService{repo: s.repo}
}
