// Package hkp provides a hkp (http keyserver protocol) client.
package hkp

import (
	"context"
)

// GetKey retrieves the specified key id from a hkp keyserver using the
// provided options.
func GetKey(ctx context.Context, id string, opts ...Option) ([]byte, error) {
	return New(opts...).GetKey(ctx, id)
}

// Error is a client error.
type Error string

// Error satisfies the error interface.
func (err Error) Error() string {
	return string(err)
}

// Error values.
const (
	// ErrInvalidKeyID is the invalid key id error.
	ErrInvalidKeyID Error = "invalid key id"
	// ErrInvalidParams is the invalid params error.
	ErrInvalidParams Error = "invalid params"
	// ErrInvalidScheme is the invalid scheme error.
	ErrInvalidScheme Error = "invalid scheme"
	// ErrKeyNotFound is the key not found error.
	ErrKeyNotFound Error = "key not found"
)
