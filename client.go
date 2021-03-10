package hkp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
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

func (cl *Client) GetKeys(ctx context.Context, ids ...string) ([]byte, error) {
	buf := new(bytes.Buffer)
	for _, id := range ids {
		key, err := cl.GetKey(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve key %q: %w", id, err)
		}
		if _, err := buf.Write(key); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
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

// WithSksKeyserversPool is a hkp client option to use the sks-keyservers.net
// pool.
func WithSksKeyserversPool() Option {
	return func(cl *Client) {
		rootCAs := x509.NewCertPool()
		_ = rootCAs.AppendCertsFromPEM(skskeyserversCA)
		cl.keyserver = `https://hkps.pool.sks-keyservers.net`
		cl.cl.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
			},
		}
	}
}

//go:embed sks-keyservers.netCA.pem
var skskeyserversCA []byte
