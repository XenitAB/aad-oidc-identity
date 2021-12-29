package config

import (
	"github.com/alexflint/go-arg"
)

//nolint:lll // line length makes sense here
type Config struct {
	Address              string `arg:"--address,env:ADDRESS" default:"0.0.0.0" help:"the address to use for the http listener"`
	Port                 int    `arg:"--port,env:PORT" default:"8080" help:"the port to use for the http listener"`
	MetricsPort          int    `arg:"--metrics-port,env:METRICS_PORT" default:"8081" help:"the metrics port to use for the http listener"`
	TokenAudience        string `arg:"--token-audience,env:TOKEN_AUDIENCE,required" help:"the audience the token is required to contain"`
	Environment          string `arg:"--environment,env:ENVIRONMENT" default:"local" help:"the environment the application is running in currently"`
	ExternalIssuer       string `arg:"--external-issuer,env:EXTERNAL_ISSUER,required" help:"the external issuer uri"`
	AzureDefaultTenantID string `arg:"--azure-default-tenant-id,env:AZURE_DEFAULT_TENANT_ID,required" help:"the default azure tenant id to issue tokens for"`
}

func Load(args []string) (Config, error) {
	argCfg := arg.Config{
		Program:   "aad-oidc-identity",
		IgnoreEnv: false,
	}

	var cfg Config
	parser, err := arg.NewParser(argCfg, &cfg)
	if err != nil {
		return Config{}, err
	}

	err = parser.Parse(args)
	if err != nil {
		return Config{}, err
	}

	return cfg, nil
}
