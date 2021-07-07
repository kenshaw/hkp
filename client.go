package hkp

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
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
	// build request
	req, err := http.NewRequest("GET", urlstr, nil)
	if err != nil {
		return nil, err
	}
	// execute
	res, err := cl.cl.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	// check status
	if res.StatusCode != http.StatusOK {
		return nil, ErrKeyNotFound
	}
	return ioutil.ReadAll(res.Body)
}

// idRE matches key ids.
var idRE = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// GetKeys retrieves the key ids.
func (cl *Client) GetKeys(ctx context.Context, ids ...string) ([]byte, error) {
	buf := new(bytes.Buffer)
	w, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create armor writer: %w", err)
	}
	for _, id := range ids {
		key, err := cl.GetKey(ctx, id)
		if err != nil {
			defer w.Close()
			return nil, fmt.Errorf("unable to retrieve key %s: %w", id, err)
		}
		block, err := armor.Decode(bytes.NewBuffer(key))
		if err != nil {
			defer w.Close()
			return nil, fmt.Errorf("unable to decode key %s: %w", id, err)
		}
		if _, err := io.Copy(w, block.Body); err != nil {
			defer w.Close()
			return nil, fmt.Errorf("unable to copy block for key %s: %w", id, err)
		}
	}
	// close
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("unable to close writer: %w", err)
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
