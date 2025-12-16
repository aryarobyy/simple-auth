package repository

import (
	"auth/internal/model"
	"context"
	"database/sql"

	"github.com/jmoiron/sqlx"
)

type UserRepo interface {
	Create(ctx context.Context, user model.User) (*model.User, error)
	GetById(ctx context.Context, id int) (*model.User, error)
	GetByUsername(ctx context.Context, username string) (*model.User, error)
}

type userRepo struct {
	db *sqlx.DB
}

func NewUserRepo(db *sqlx.DB) *userRepo {
	return &userRepo{db: db}
}

func (s *userRepo) Create(ctx context.Context, user model.User) (*model.User, error) {
	query := `
		INSERT INTO users (name, username, password, role)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, username, role, created_at
	`

	var result model.User
	err := s.db.QueryRowContext(
		ctx,
		query,
		user.Name,
		user.Username,
		user.Password,
		model.RoleUser,
	).Scan(
		&result.ID,
		&result.Name,
		&result.Username,
		&result.Role,
		&result.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

func (s *userRepo) GetById(ctx context.Context, id int) (*model.User, error) {
	user := model.User{}
	if err := s.db.GetContext(
		ctx,
		&user,
		`SELECT * FROM users WHERE id = $1`,
		id,
	); err != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}

		return nil, err
	}
	return &user, nil
}

func (s *userRepo) GetByUsername(ctx context.Context, username string) (*model.User, error) {
	user := model.User{}
	if err := s.db.GetContext(
		ctx,
		&user,
		`SELECT * FROM users WHERE username = $1`,
		username,
	); err != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}

		return nil, err
	}
	return &user, nil
}
