package repository

import "github.com/jmoiron/sqlx"

type Repository interface {
	User() userRepo
	Auth() authRepo
}

type repository struct {
	db *sqlx.DB
}

func NewRepository(db *sqlx.DB) *repository {
	return &repository{
		db: db,
	}
}

func (r *repository) Auth() authRepo {
	return authRepo{db: r.db}
}

func (r *repository) User() userRepo {
	return userRepo{db: r.db}
}
