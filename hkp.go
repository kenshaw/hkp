// Package hkp provides a hkp (http keyserver protocol) client.
package hkp

import (
	"context"
	"net/url"
	"regexp"
	"strings"
)

var schemeRE = regexp.MustCompile(`(?i)^(http|hkp)s?://`)

// ParseURL parses a keyserver url, adding the specified params as query
// values.
func ParseURL(urlstr string, query ...string) (string, error) {
	if len(query)%2 != 0 {
		return "", ErrInvalidParams
	}
	if !strings.Contains(urlstr, "://") {
		urlstr = "hkps://" + urlstr
	}
	if !schemeRE.MatchString(urlstr) {
		return "", ErrInvalidScheme
	}
	u, err := url.Parse(urlstr)
	if err != nil {
		return "", err
	}
	// set path and query
	q := url.Values{}
	for i := 0; i < len(query); i += 2 {
		q.Set(query[i], query[i+1])
	}
	u.Scheme, u.Path, u.RawQuery = "https", "/pks/lookup", q.Encode()
	return u.String(), nil
}

// GetKey retrieves the specified key id from a hkp keyserver using the
// provided options.
func GetKey(ctx context.Context, id string, opts ...Option) ([]byte, error) {
	return New(opts...).GetKey(ctx, id)
}

// GetKeys retrieves the specified key ids from the default hkp keyserver.
func GetKeys(ctx context.Context, ids ...string) ([]byte, error) {
	return New().GetKeys(ctx, ids...)
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
