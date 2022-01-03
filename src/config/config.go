package config

import (
	"github.com/alexflint/go-arg"
)

//nolint:lll // line length makes sense here
type Config struct {
	Address               string `arg:"--address,env:ADDRESS" help:"the address to use for the http listener"`
	InternalPort          int    `arg:"--internal-port,env:INTERNAL_PORT" help:"the internal port to use for the http listener"`
	ExternalPort          int    `arg:"--external-port,env:EXTERNAL_PORT" help:"the external port to use for the http listener"`
	TokenAudience         string `arg:"--token-audience,env:TOKEN_AUDIENCE" help:"the audience the token is required to contain"`
	Environment           string `arg:"--environment,env:ENVIRONMENT" default:"local" help:"the environment the application is running in currently"`
	ExternalIssuer        string `arg:"--external-issuer,env:EXTERNAL_ISSUER" help:"the external issuer uri"`
	AzureDefaultTenantID  string `arg:"--azure-default-tenant-id,env:AZURE_DEFAULT_TENANT_ID,required" help:"the default azure tenant id to issue tokens for"`
	Namespace             string `arg:"--namespace,env:NAMESPACE,required" help:"the namespace the service is running in"`
	CertificateSecretName string `arg:"--rsa-key-secret-name,env:RSA_KEY_SECRET_NAME" default:"aad-oidc-identity-jwks" help:"the kubernetes secret name for the RSA key used to create the jwks"`
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
