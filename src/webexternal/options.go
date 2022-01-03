package webexternal

import "fmt"

type options struct {
	address string
	port    int
	issuer  string
	key     publicKeyGetter
}

func (opts *options) Validate() error {
	if opts.address == "" {
		return fmt.Errorf("address is empty")
	}

	if opts.port == 0 {
		return fmt.Errorf("port is not set")
	}

	if opts.issuer == "" {
		return fmt.Errorf("issuer is empty")
	}

	if opts.key == nil {
		return fmt.Errorf("key is nil")
	}

	return nil
}

func newOptions(setters ...Option) (*options, error) {
	opts := &options{
		address: "0.0.0.0",
		port:    8081,
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

func WithIssuer(opt string) Option {
	return func(opts *options) {
		if opt != "" {
			opts.issuer = opt
		}
	}
}

func WithPublicKeyGetter(opt publicKeyGetter) Option {
	return func(opts *options) {
		if opt != nil {
			opts.key = opt
		}
	}
}
