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
	ts, err := NewTokenService(cfg)
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
