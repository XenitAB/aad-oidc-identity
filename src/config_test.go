package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	cases := []struct {
		testDescription       string
		args                  []string
		expectedConfig        config
		expectedErrorContains string
	}{
		{
			testDescription:       "failing - no args",
			args:                  []string{},
			expectedConfig:        config{},
			expectedErrorContains: "is required",
		},
		{
			testDescription: "successful - all required fields set",
			args: []string{
				"--token-issuer=http://fake-issuer.foobar",
				"--token-audience=fake-audience",
			},
			expectedConfig: config{
				Address:       "0.0.0.0",
				Port:          8080,
				MetricsPort:   8081,
				TokenIssuer:   "http://fake-issuer.foobar",
				TokenAudience: "fake-audience",
				Environment:   "local",
				CAPath:        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
				TokenPath:     "/var/run/secrets/kubernetes.io/serviceaccount/token",
			},
			expectedErrorContains: "",
		},
	}

	for i, c := range cases {
		t.Logf("Test #%d: %s", i, c.testDescription)

		cfg, err := loadConfig(c.args)

		if c.expectedErrorContains != "" {
			require.Error(t, err)
			require.Contains(t, err.Error(), c.expectedErrorContains)
		} else {
			require.Equal(t, c.expectedConfig, cfg)
		}
	}
}
