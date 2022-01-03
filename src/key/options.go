package key

import (
	"crypto/rsa"
	"fmt"
)

type options struct {
	rsaKey *rsa.PrivateKey
}

func (opts *options) Validate() error {
	if opts.rsaKey == nil {
		return fmt.Errorf("rsaKey is nil")
	}

	return nil
}

func newOptions(setters ...Option) (*options, error) {
	opts := &options{}

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

func WithRSAKey(opt *rsa.PrivateKey) Option {
	return func(opts *options) {
		if opt != nil {
			opts.rsaKey = opt
		}
	}
}
