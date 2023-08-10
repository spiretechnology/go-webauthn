package store

import (
	"context"
)

type User struct {
	ID          string
	Name        string
	DisplayName string
}

type Users interface {
	GetUser(ctx context.Context, id string) (*User, error)
}
