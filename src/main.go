package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/xenitab/aad-oidc-identity/src/provider"
	"golang.org/x/sync/errgroup"
)

func main() {
	cfg, err := loadConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to load config: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	err = run(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "application returned an error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config) error {
	k, err := newKubeReader(cfg, "")
	if err != nil {
		return err
	}

	rsaKey, err := k.getCertificateFromSecret(context.Background(), "default", "aad-oidc-identity-jwks")
	if err != nil {
		return err
	}

	jwks, err := newJwksHandler(rsaKey)
	if err != nil {
		return err
	}

	issuer, err := k.getKubeIssuer()
	if err != nil {
		return err
	}

	httpClient := k.getKubeHttpClient()

	providerHandlerFuncs, err := newProviderHandlerFuncs(cfg, k, jwks, issuer)
	if err != nil {
		return err
	}

	ts, err := NewTokenService(cfg, issuer, httpClient, jwks, providerHandlerFuncs)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if err := ts.server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			return err
		}

		return nil
	})

	stopChan := make(chan os.Signal, 2)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGPIPE)

	var doneMsg string
	select {
	case sig := <-stopChan:
		doneMsg = fmt.Sprintf("os.Signal (%s)", sig)
	case <-ctx.Done():
		doneMsg = "context"
	}

	cancel()

	fmt.Printf("server shutdown initiated by: %s\n", doneMsg)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	g.Go(func() error {
		if err := ts.server.Shutdown(shutdownCtx); err != nil {
			return err
		}

		return nil
	})

	err = g.Wait()
	if err != nil {
		return fmt.Errorf("error groups error: %w", err)
	}

	return nil
}

func newProviderHandlerFuncs(cfg config, k *kubeReader, jwks *jwksHandler, issuer string) (map[string]gin.HandlerFunc, error) {
	azure, err := provider.NewAzureProvider(k, jwks, cfg.DefaultTenantID)
	if err != nil {
		return nil, err
	}

	aws, err := provider.NewAwsProvider(k, jwks)
	if err != nil {
		return nil, err
	}

	google, err := provider.NewGoogleProvider(k, jwks)
	if err != nil {
		return nil, err
	}

	return map[string]gin.HandlerFunc{
		"azure":  azure.NewHandlerFunc(issuer),
		"aws":    aws.NewHandlerFunc(issuer),
		"google": google.NewHandlerFunc(issuer),
	}, nil
}
