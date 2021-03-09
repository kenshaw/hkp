package hkp

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// DefaultKeyserver is the default keyserver used by hkp clients.
const DefaultKeyserver = "keyserver.ubuntu.com"

// Client is a hkp (http keyserver protocol) client.
type Client struct {
	cl        *http.Client
	keyserver string
}

// New creates a new hkp client.
func New(opts ...Option) *Client {
	cl := &Client{
		cl:        &http.Client{},
		keyserver: DefaultKeyserver,
	}
	for _, o := range opts {
		o(cl)
	}
	return cl
}

var idRE = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// GetKey returns the specified key id from a hkp keyserver.
func (cl *Client) GetKey(ctx context.Context, id string) ([]byte, error) {
	if id == "" || !idRE.MatchString(id) {
		return nil, ErrInvalidKeyID
	}
	urlstr, err := ParseURL(
		cl.keyserver,
		"op", "get",
		"options", "mr",
		"search", "0x"+id,
	)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", urlstr, nil)
	if err != nil {
		return nil, err
	}
	res, err := cl.cl.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, ErrKeyNotFound
	}
	return ioutil.ReadAll(res.Body)
}

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

// Option is a hkp client option.
type Option func(*Client)

// WithHTTPClient is a hkp client option to set the underlying http client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(cl *Client) {
		cl.cl = httpClient
	}
}

// WithTransport is a hkp client option to set the underlying http client
// transport.
func WithTransport(transport http.RoundTripper) Option {
	return func(cl *Client) {
		cl.cl.Transport = transport
	}
}

// WithKeyserver is a hkp client option to set the keyserver.
func WithKeyserver(keyserver string) Option {
	return func(cl *Client) {
		cl.keyserver = keyserver
	}
}
