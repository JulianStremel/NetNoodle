// nn-host-updater runs on the host as root; the server never gets its socket.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/JulianStremel/netnoodle/internal/updater"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "nn-host-updater:", e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: nn-host-updater run-once|check|rollback --to ID|status [--config FILE]")
	}
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	config := flags.String("config", "/etc/nn-host-updater/config.json", "strict host configuration")
	to := flags.String("to", "", "successful update request ID to roll back")
	if e := flags.Parse(os.Args[2:]); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	c, e := updater.LoadConfig(*config)
	if e != nil {
		return e
	}
	u, e := updater.New(c, nil)
	if e != nil {
		return e
	}
	if e = u.Init(); e != nil {
		return e
	}
	lock, e := os.OpenFile(filepath.Join(c.SharedDir, "state", "updater.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = lockFile(lock); e != nil {
		return fmt.Errorf("another updater is running: %w", e)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch command {
	case "run-once":
		return u.RunOnce(ctx)
	case "check":
		return u.Check(ctx)
	case "status":
		entries, e := os.ReadDir(filepath.Join(c.SharedDir, "status"))
		if e != nil {
			return e
		}
		out := map[string]json.RawMessage{}
		for _, f := range entries {
			if f.Name() == "available.json" {
				var a updater.Available
				if e = updater.ReadJSON(c.SharedDir, &a, "status", f.Name()); e != nil {
					return e
				}
				b, _ := json.Marshal(a)
				out[f.Name()] = b
			} else if filepath.Ext(f.Name()) == ".json" && updater.ValidID(f.Name()[:len(f.Name())-5]) {
				var s updater.Status
				if e = updater.ReadJSON(c.SharedDir, &s, "status", f.Name()); e != nil {
					return e
				}
				b, _ := json.Marshal(s)
				out[s.ID] = b
			}
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	case "rollback":
		if !updater.ValidID(*to) {
			return fmt.Errorf("rollback requires --to ID")
		}
		var b [16]byte
		if _, e = rand.Read(b[:]); e != nil {
			return e
		}
		r := updater.Request{ID: hex.EncodeToString(b[:]), Kind: "rollback", Channel: c.Channel, To: *to, RequestedBy: "host-root", RequestedAt: time.Now().UTC()}
		if e = updater.WriteJSON(c.SharedDir, r, "requests", r.ID+".json"); e != nil {
			return e
		}
		return u.RunOnce(ctx)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}
