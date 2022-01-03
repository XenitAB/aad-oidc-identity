package webinternal

import (
	"fmt"
	"net/http"
)

type options struct {
	address        string
	port           int
	issuerInternal string
	issuerExternal string
	audience       string
	httpClient     *http.Client
	// FIXME: Better name
	providerTokenGetter map[string]TokenGetter
}

func (opts *options) Validate() error {
	if opts.address == "" {
		return fmt.Errorf("address is empty")
	}

	if opts.port == 0 {
		return fmt.Errorf("port is not set")
	}

	if opts.issuerInternal == "" {
		return fmt.Errorf("issuerInternal is empty")
	}

	if opts.issuerExternal == "" {
		return fmt.Errorf("issuerExternal is empty")
	}

	if opts.audience == "" {
		return fmt.Errorf("audience is empty")
	}

	if opts.httpClient == nil {
		return fmt.Errorf("httpClient is nil")
	}

	if len(opts.providerTokenGetter) == 0 {
		return fmt.Errorf("providerTokenGetter is not set")
	}

	return nil
}

func newOptions(setters ...Option) (*options, error) {
	opts := &options{
		address: "0.0.0.0",
		port:    8080,
	}

	for _, setter := range setters {
		setter(opts)
	}

	err := opts.Validate()
	if err != nil {
		return nil, err
	}

	return opts, nil
}

type Option func(*options)

func WithAddress(opt string) Option {
	return func(opts *options) {
		if opt != "" {
			opts.address = opt
		}
	}
}

func WithPort(opt int) Option {
	return func(opts *options) {
		if opt != 0 {
			opts.port = opt
		}
	}
}

func WithIssuerInternal(opt string) Option {
	return func(opts *options) {
		if opt != "" {
			opts.issuerInternal = opt
		}
	}
}

func WithIssuerExternal(opt string) Option {
	return func(opts *options) {
		if opt != "" {
			opts.issuerExternal = opt
		}
	}
}

func WithAudience(opt string) Option {
	return func(opts *options) {
		if opt != "" {
			opts.audience = opt
		}
	}
}

func WithHttpClient(opt *http.Client) Option {
	return func(opts *options) {
		if opt != nil {
			opts.httpClient = opt
		}
	}
}

func WithProviderTokenGetter(opt map[string]TokenGetter) Option {
	return func(opts *options) {
		if len(opt) != 0 {
			opts.providerTokenGetter = opt
		}
	}
}
