package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/JulianStremel/netnoodle/internal/actor"
	_ "github.com/JulianStremel/netnoodle/internal/actor/hostactor"
	_ "github.com/JulianStremel/netnoodle/internal/actor/logactor"
	_ "github.com/JulianStremel/netnoodle/internal/actor/pveactor"
	_ "github.com/JulianStremel/netnoodle/internal/actor/unifiactor"
	"github.com/JulianStremel/netnoodle/internal/client"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	e := command(ctx, os.Args[1:])
	if e != nil && !errors.Is(e, context.Canceled) {
		fmt.Fprintln(os.Stderr, "nn-actor:", e)
		os.Exit(1)
	}
}
func command(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: nn-actor enroll|run [flags]")
	}
	switch args[0] {
	case "enroll":
		fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
		server := fs.String("server", "", "server HTTPS URL")
		fp := fs.String("fingerprint", "", "server certificate SHA-256 fingerprint")
		name := fs.String("name", "", "actor name")
		key := fs.String("order-key", "", "expected base64 order public key")
		out := fs.String("creds", "nn-actor-creds.json", "credentials file")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		token := os.Getenv("NN_JOIN_TOKEN")
		if *server == "" || *fp == "" || token == "" {
			return errors.New("-server, -fingerprint and NN_JOIN_TOKEN are required")
		}
		c, e := client.Enroll(ctx, *server, *fp, token, *name)
		if e != nil {
			return e
		}
		pub, e := base64.StdEncoding.DecodeString(c.OrderKey)
		if e != nil || len(pub) != ed25519.PublicKeySize || c.Role != "actor" {
			return errors.New("enrollment did not return actor credentials and an order key")
		}
		if *key != "" && *key != c.OrderKey {
			return errors.New("order key does not match -order-key")
		}
		if e = client.SaveCredentials(*out, c); e != nil {
			return e
		}
		fmt.Printf("enrolled actor %q; credentials in %s\n", c.Name, *out)
		return nil
	case "run":
		fs := flag.NewFlagSet("run", flag.ContinueOnError)
		file := fs.String("config", "actor.json", "actor config file")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		f, e := os.Open(*file)
		if e != nil {
			return e
		}
		defer f.Close()
		var cfg actor.Config
		d := json.NewDecoder(f)
		d.DisallowUnknownFields()
		if e = d.Decode(&cfg); e != nil {
			return e
		}
		if cfg.Credentials == "" {
			cfg.Credentials = "nn-actor-creds.json"
		}
		creds, e := client.LoadCredentials(cfg.Credentials)
		if e != nil {
			return e
		}
		r, e := actor.NewRunner(cfg, creds)
		if e != nil {
			return e
		}
		c, e := client.New(creds)
		if e != nil {
			return e
		}
		return r.Run(ctx, c)
	default:
		return errors.New("usage: nn-actor enroll|run [flags]")
	}
}
