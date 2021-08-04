package udpsocket

import (
	"context"
	"github.com/google/uuid"
)

// An interface for authenticating the client token
type AuthClient interface {
	Authenticate(context.Context, []byte) (string, error)
}

// A simple implementation of auth client if no authentication is required
type DefaultAuthClient struct{}

// Only generates a new UUID for the user without any authentication
func (a *DefaultAuthClient) Authenticate(context.Context, []byte) (string, error) {
	return uuid.New().String(), nil
}
