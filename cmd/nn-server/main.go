// Command nn-server is the netnoodle central server: web UI, operator API,
// ingest of observations, threat matching, decisions and the actor queue.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/JulianStremel/netnoodle/internal/decide"
	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/notify"
	_ "github.com/JulianStremel/netnoodle/internal/plugins" // built-in plug-ins
	"github.com/JulianStremel/netnoodle/internal/pull"
	pullhttps "github.com/JulianStremel/netnoodle/internal/pull/https"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/server"
	"github.com/JulianStremel/netnoodle/internal/store/sqlite"
	"github.com/JulianStremel/netnoodle/web"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nn-server:", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", "netnoodle.json", "config file (optional)")
	resetAdmin := flag.Bool("reset-admin", false, "set a new random password for user admin and exit")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg, err := server.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := sqlite.Open(ctx, filepath.Join(cfg.DataDir, "netnoodle.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	if *resetAdmin {
		return doResetAdmin(ctx, st)
	}

	pw, err := server.EnsureAdmin(ctx, st)
	if err != nil {
		return err
	}
	if pw != "" {
		fmt.Fprintf(os.Stderr, "\n  First start. Created user \"admin\" with password: %s\n  This password is shown only once.\n\n", pw)
	}

	cert, fp, err := server.LoadOrCreateCert(cfg.DataDir)
	if err != nil {
		return err
	}
	log.Info("tls", "fingerprint", fp)

	srv := server.New(cfg, st, web.FS(), fp, log)

	notifiers, err := registry.BuildAll(notify.Registry, cfg.Notifiers)
	if err != nil {
		return err
	}
	srv.SetNotifiers(notifiers)
	matchers, err := registry.BuildAll(intel.Matchers, cfg.Matchers)
	if err != nil {
		return err
	}
	enrichers, err := registry.BuildAll(intel.Enrichers, cfg.Enrichers)
	if err != nil {
		return err
	}
	srv.SetIntel(matchers, enrichers)
	deciders, err := registry.BuildAll(decide.Deciders, cfg.Deciders)
	if err != nil {
		return err
	}
	guards, err := registry.BuildAll(decide.Guards, cfg.Guards)
	if err != nil {
		return err
	}
	srv.SetDecide(deciders, guards)
	go srv.RunIntel(ctx, cfg.IntelRefresh.Duration)
	if err := srv.RunSources(ctx, cfg.Sources); err != nil {
		return err
	}
	pullCert, pullFP, err := server.LoadOrCreatePullCert(cfg.DataDir)
	if err != nil {
		return err
	}
	log.Info("pull client certificate", "fingerprint", pullFP)
	srv.SetPull(map[string]pull.Transport{"https": pullhttps.New(pullCert, pullFP)}, pullFP)
	go srv.RunPull(ctx)
	go srv.RunMaintenance(ctx, cfg.ObservationRetention.Duration)

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", "https://"+cfg.Listen)
		errc <- hs.ListenAndServeTLS("", "")
	}()

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return hs.Shutdown(sctx)
	}
	return nil
}

func doResetAdmin(ctx context.Context, st *sqlite.DB) error {
	u, err := st.UserByName(ctx, "admin")
	if err != nil {
		return fmt.Errorf("user admin: %w", err)
	}
	pw := server.RandomToken(15)
	h, err := server.HashPassword(pw)
	if err != nil {
		return err
	}
	if err := st.SetPassword(ctx, u.ID, h); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "New password for admin: %s\n", pw)
	return nil
}
