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
	"github.com/xenitab/aad-oidc-identity/src/config"
	"github.com/xenitab/aad-oidc-identity/src/data"
	"github.com/xenitab/aad-oidc-identity/src/key"
	"github.com/xenitab/aad-oidc-identity/src/provider"
	"github.com/xenitab/aad-oidc-identity/src/webserver"
	"golang.org/x/sync/errgroup"
)

func main() {
	cfg, err := config.Load(os.Args[1:])
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

func run(ctx context.Context, cfg config.Config) error {
	dataReader, err := data.NewDataReader(cfg, "")
	if err != nil {
		return err
	}

	rsaKey, err := dataReader.GetCertificateFromSecret(context.Background(), "default", "aad-oidc-identity-jwks")
	if err != nil {
		return err
	}

	keyHandler, err := key.NewKeyHandler(rsaKey)
	if err != nil {
		return err
	}

	internalIssuer, err := dataReader.GetInternalIssuer()
	if err != nil {
		return err
	}

	httpClient := dataReader.GetHttpClient()

	providerHandlerFuncs, err := newProviderHandlerFuncs(cfg, dataReader, keyHandler)
	if err != nil {
		return err
	}

	srv, err := webserver.NewWebServer(cfg, internalIssuer, httpClient, keyHandler, providerHandlerFuncs)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
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
		if err := srv.Shutdown(shutdownCtx); err != nil {
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

func newProviderHandlerFuncs(cfg config.Config, dataReader *data.DataReader, keyHandler *key.KeyHandler) (map[string]gin.HandlerFunc, error) {
	azure, err := provider.NewAzureProvider(dataReader, keyHandler, cfg.AzureDefaultTenantID)
	if err != nil {
		return nil, err
	}

	aws, err := provider.NewAwsProvider(dataReader, keyHandler)
	if err != nil {
		return nil, err
	}

	google, err := provider.NewGoogleProvider(dataReader, keyHandler)
	if err != nil {
		return nil, err
	}

	return map[string]gin.HandlerFunc{
		"azure":  azure.NewHandlerFunc(cfg.ExternalIssuer),
		"aws":    aws.NewHandlerFunc(cfg.ExternalIssuer),
		"google": google.NewHandlerFunc(cfg.ExternalIssuer),
	}, nil
}
