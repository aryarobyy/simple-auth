package repository

import (
	"context"
	"database/sql"

	"auth/internal/model"

	"github.com/jmoiron/sqlx"
)

type UserRepo interface {
	GetById(ctx context.Context, id int) (*model.User, error)
	GetByUsername(ctx context.Context, username string) (*model.User, error)
	GetMany(ctx context.Context, limit int, offset int) ([]model.User, error)
}

type userRepo struct {
	db *sqlx.DB
}

func NewUserRepo(db *sqlx.DB) *userRepo {
	return &userRepo{db: db}
}

func (s *userRepo) GetById(ctx context.Context, id int) (*model.User, error) {
	user := model.User{}
	if err := s.db.GetContext(
		ctx,
		&user,
		`SELECT * FROM users WHERE id = $1`,
		id,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, err
		}

		return nil, err
	}
	return &user, nil
}

func (s *userRepo) GetByUsername(ctx context.Context, username string) (*model.User, error) {
	user := model.User{}
	// var dest int
	if err := s.db.GetContext(
		ctx,
		&user,
		`SELECT * FROM users WHERE username = $1`,
		username,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, err
		}

		return nil, err
	}
	return &user, nil
}

func (s *userRepo) GetMany(ctx context.Context, limit int, offset int) ([]model.User, error) {
	user := []model.User{}

	if err := s.db.GetContext(
		ctx,
		&user,
		`SELECT * FROM users LIMIT $1 OFFSET $2`,
		limit,
		offset,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, err
		}

		return nil, err
	}
	return user, nil
}
