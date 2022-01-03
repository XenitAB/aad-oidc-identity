package provider

import "fmt"

type options struct {
	dataGetter                 dataGetter
	privateKeyGetter           privateKeyGetter
	azureDefaultTenantId       string
	azureDefaultScope          string
	googleDefaultScope         string
	googleDefaultProjectNumber string
	googleDefaultPoolId        string
	googleDefaultProviderId    string
}

func (opts *options) Validate() error {
	if opts.dataGetter == nil {
		return fmt.Errorf("data is nil")
	}

	if opts.privateKeyGetter == nil {
		return fmt.Errorf("key is nil")
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

func WithDataGetter(opt dataGetter) Option {
	return func(opts *options) {
		if opt != nil {
			opts.dataGetter = opt
		}
	}
}

func WithPrivateKeyGetter(opt privateKeyGetter) Option {
	return func(opts *options) {
		if opt != nil {
			opts.privateKeyGetter = opt
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
