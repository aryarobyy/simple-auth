package model

import "time"

type User struct {
	ID        int        `json:"id"`
	Name      string     `json:"name"`
	Username  string     `json:"username"`
	Password  string     `json:"password"`
	Role      Role       `json:"role"`
	CreatedAt *time.Time `json:"created_at"`
	UpdatedAt *time.Time `json:"updated_at"`
}

type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)
