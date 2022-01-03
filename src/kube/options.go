package kube

import "fmt"

type options struct {
	configPath            string
	namespace             string
	certificateSecretName string
}

func (opts *options) Validate() error {
	if opts.namespace == "" {
		return fmt.Errorf("namespace is empty")
	}

	if opts.certificateSecretName == "" {
		return fmt.Errorf("certificateSecretName is empty")
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

func WithConfigPath(opt string) Option {
	return func(opts *options) {
		if opt != "" {
			opts.configPath = opt
		}
	}
}

func WithNamespace(opt string) Option {
	return func(opts *options) {
		if opt != "" {
			opts.namespace = opt
		}
	}
}

func WithCertificateSecretName(opt string) Option {
	return func(opts *options) {
		if opt != "" {
			opts.certificateSecretName = opt
		}
	}
}
