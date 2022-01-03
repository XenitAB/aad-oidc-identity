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

	"github.com/xenitab/aad-oidc-identity/src/config"
	"github.com/xenitab/aad-oidc-identity/src/key"
	"github.com/xenitab/aad-oidc-identity/src/kube"
	"github.com/xenitab/aad-oidc-identity/src/provider"
	"github.com/xenitab/aad-oidc-identity/src/webexternal"
	"github.com/xenitab/aad-oidc-identity/src/webinternal"
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g, ctx := errgroup.WithContext(ctx)

	kubeClient, err := kube.NewClient(cfg, "")
	if err != nil {
		return err
	}

	rsaKeyCtx, rsaKeyCtxCancel := context.WithTimeout(ctx, 5*time.Second)
	defer rsaKeyCtxCancel()

	rsaKey, err := kubeClient.GetCertificate(rsaKeyCtx)
	if err != nil {
		return err
	}

	keyHandler, err := key.NewHandler(rsaKey)
	if err != nil {
		return err
	}

	internalIssuer, err := kubeClient.GetInternalIssuer()
	if err != nil {
		return err
	}

	httpClient := kubeClient.GetHttpClient()

	providers, err := newProviders(cfg, kubeClient, keyHandler)
	if err != nil {
		return err
	}

	iWeb, err := webinternal.NewServer(cfg, internalIssuer, httpClient, providers)
	if err != nil {
		return err
	}

	eWeb, err := webexternal.NewServer(
		webexternal.WithAddress(cfg.Address),
		webexternal.WithPort(cfg.ExternalPort),
		webexternal.WithIssuer(cfg.ExternalIssuer),
		webexternal.WithPublicKeyGetter(keyHandler))
	if err != nil {
		return err
	}

	g.Go(func() error {
		if err := iWeb.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			return err
		}

		return nil
	})

	g.Go(func() error {
		if err := eWeb.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
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
		if err := eWeb.Shutdown(shutdownCtx); err != nil {
			return err
		}

		return nil
	})

	g.Go(func() error {
		if err := iWeb.Shutdown(shutdownCtx); err != nil {
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

func newProviders(cfg config.Config, kubeClient *kube.KubeClient, keyHandler *key.KeyHandler) (map[string]webinternal.TokenGetter, error) {
	azure, err := provider.NewAzureProvider(kubeClient, keyHandler, cfg.AzureDefaultTenantID)
	if err != nil {
		return nil, err
	}

	aws, err := provider.NewAwsProvider(kubeClient, keyHandler)
	if err != nil {
		return nil, err
	}

	google, err := provider.NewGoogleProvider(kubeClient, keyHandler)
	if err != nil {
		return nil, err
	}

	return map[string]webinternal.TokenGetter{
		"azure":  azure,
		"aws":    aws,
		"google": google,
	}, nil
}
