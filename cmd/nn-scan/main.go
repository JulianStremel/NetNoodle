// Command nn-scan scans subnets and sends the results to nn-server.
//
//	nn-scan enroll -server https://host:7443 -fingerprint <hex> -token <join token> [-name scan-lan]
//	nn-scan run    -config scan.json [-once]
//	nn-scan scan   -cidr 192.168.1.0/24          (print JSON, no server)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/JulianStremel/netnoodle/internal/client"
	"github.com/JulianStremel/netnoodle/internal/discovery/scan"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/version"
)

const defaultCreds = "nn-scan-creds.json"

// fileConfig is the nn-scan config file.
type fileConfig struct {
	Credentials string   `json:"credentials"`
	CIDRs       []string `json:"cidrs"`
	Ports       []int    `json:"ports,omitempty"`
	Interval    string   `json:"interval,omitempty"` // e.g. "15m"; empty = once
	TimeoutMS   int      `json:"timeout_ms,omitempty"`
	Concurrency int      `json:"concurrency,omitempty"`
	MaxHosts    int      `json:"max_hosts,omitempty"`
	NoDNS       bool     `json:"no_dns,omitempty"`
	NoBanners   bool     `json:"no_banners,omitempty"`
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version" || os.Args[1] == "-version") {
		fmt.Println(version.Version, version.Protocol)
		return
	}
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "enroll":
		err = cmdEnroll(ctx, os.Args[2:])
	case "run":
		err = cmdRun(ctx, os.Args[2:])
	case "scan":
		err = cmdScan(ctx, os.Args[2:])
	default:
		usage()
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "nn-scan:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: nn-scan enroll|run|scan [flags]  (use -h after a command for its flags)")
	os.Exit(2)
}

func cmdEnroll(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "server URL, e.g. https://10.0.0.2:7443")
	fp := fs.String("fingerprint", "", "SHA-256 fingerprint of the server certificate")
	token := fs.String("token", "", "join token (better: set NN_JOIN_TOKEN, so it is not visible in the process list)")
	name := fs.String("name", "", "peer name (if the join token has no fixed name)")
	out := fs.String("creds", defaultCreds, "where to write the credentials")
	fs.Parse(args)
	if *token == "" {
		*token = os.Getenv("NN_JOIN_TOKEN")
	}
	if *server == "" || *fp == "" || *token == "" {
		return errors.New("-server, -fingerprint and -token are required")
	}
	c, err := client.Enroll(ctx, *server, *fp, *token, *name)
	if err != nil {
		return err
	}
	if err := client.SaveCredentials(*out, c); err != nil {
		return err
	}
	fmt.Printf("enrolled as %q (role %s); credentials in %s\n", c.Name, c.Role, *out)
	return nil
}

func scannerFrom(fc fileConfig) (*scan.Scanner, error) {
	cfg := scan.Config{CIDRs: fc.CIDRs, Ports: fc.Ports, Concurrency: fc.Concurrency, MaxHosts: fc.MaxHosts, NoDNS: fc.NoDNS, NoBanners: fc.NoBanners}
	if fc.TimeoutMS > 0 {
		cfg.Timeout = time.Duration(fc.TimeoutMS) * time.Millisecond
	}
	return scan.New(cfg)
}

func cmdRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "nn-scan.json", "config file")
	once := fs.Bool("once", false, "scan once and exit")
	fs.Parse(args)

	b, err := os.ReadFile(*cfgPath)
	if err != nil {
		return err
	}
	var fc fileConfig
	if err := json.Unmarshal(b, &fc); err != nil {
		return fmt.Errorf("%s: %w", *cfgPath, err)
	}
	if fc.Credentials == "" {
		fc.Credentials = defaultCreds
	}
	creds, err := client.LoadCredentials(fc.Credentials)
	if err != nil {
		return err
	}
	cl, err := client.New(creds)
	if err != nil {
		return err
	}
	sc, err := scannerFrom(fc)
	if err != nil {
		return err
	}
	var every time.Duration
	if fc.Interval != "" && !*once {
		if every, err = time.ParseDuration(fc.Interval); err != nil {
			return fmt.Errorf("interval: %w", err)
		}
		if every < time.Minute {
			every = time.Minute
		}
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	for {
		start := time.Now()
		ents, err := sc.Scan(ctx)
		if err != nil {
			return err
		}
		obs := proto.Observation{ObservedAt: start.UTC(), Entities: ents}
		if err := cl.PostObservation(ctx, obs); err != nil {
			log.Error("send", "err", err)
		} else {
			log.Info("scan sent", "hosts", sc.Hosts(), "alive", len(ents), "took", time.Since(start).Round(time.Millisecond))
		}
		if every == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}

func cmdScan(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	cidr := fs.String("cidr", "", "comma-separated ranges or addresses")
	ports := fs.String("ports", "", "comma-separated ports (default: built-in list)")
	fs.Parse(args)
	if *cidr == "" {
		return errors.New("-cidr is required")
	}
	fc := fileConfig{CIDRs: strings.Split(*cidr, ",")}
	if *ports != "" {
		for _, p := range strings.Split(*ports, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil {
				return fmt.Errorf("bad port %q", p)
			}
			fc.Ports = append(fc.Ports, n)
		}
	}
	sc, err := scannerFrom(fc)
	if err != nil {
		return err
	}
	ents, err := sc.Scan(ctx)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(proto.Observation{Version: proto.Version, Source: "local", ObservedAt: time.Now().UTC(), Entities: ents})
}
