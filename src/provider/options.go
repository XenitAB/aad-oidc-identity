package provider

import "fmt"

type options struct {
	getServiceAccountInfo      getServiceAccountInfoFn
	getPrivateKey              getPrivateKeyFn
	azureDefaultTenantId       string
	azureDefaultScope          string
	googleDefaultScope         string
	googleDefaultProjectNumber string
	googleDefaultPoolId        string
	googleDefaultProviderId    string
}

func (opts *options) Validate() error {
	if opts.getServiceAccountInfo == nil {
		return fmt.Errorf("getServiceAccountInfo is nil")
	}

	if opts.getPrivateKey == nil {
		return fmt.Errorf("getPrivateKey is nil")
	}

	return nil
}

func newOptions(setters ...Option) (*options, error) {
	opts := &options{
		azureDefaultScope:  "https://management.core.windows.net/.default",
		googleDefaultScope: "https://www.googleapis.com/auth/cloud-platform",
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

func WithGetServiceAccountInfoFn(opt getServiceAccountInfoFn) Option {
	return func(opts *options) {
		if opt != nil {
			opts.getServiceAccountInfo = opt
		}
	}
}

func WithGetPrivateKeyFn(opt getPrivateKeyFn) Option {
	return func(opts *options) {
		if opt != nil {
			opts.getPrivateKey = opt
		}
	}
}

func WithAzureDefaultTenantId(opt string) Option {
	return func(opts *options) {
		if opt != "" {
			opts.azureDefaultTenantId = opt
		}
	}
}

func WithAzureDefaultScope(opt string) Option {
	return func(opts *options) {
		if opt != "" {
			opts.azureDefaultScope = opt
		}
	}
}

func WithGoogleDefaultScope(opt string) Option {
	return func(opts *options) {
		if opt != "" {
			opts.googleDefaultScope = opt
		}
	}
}

func WithGoogleDefaultProjectNumber(opt string) Option {
	return func(opts *options) {
		if opt != "" {
			opts.googleDefaultProjectNumber = opt
		}
	}
}

func WithGoogleDefaultPoolId(opt string) Option {
	return func(opts *options) {
		if opt != "" {
			opts.googleDefaultPoolId = opt
		}
	}
}

func WithGoogleDefaultProviderId(opt string) Option {
	return func(opts *options) {
		if opt != "" {
			opts.googleDefaultProviderId = opt
		}
	}
}
