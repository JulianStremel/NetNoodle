//go:build linux

package hostactor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestExecRunner(t *testing.T) {
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runner := nativeRunner()
	args := []string{"-test.run=^TestCommandHelper$", "--", "echo", "literal;$(shell)"}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	out, stderr, err := runner.Run(ctx, program, args, "stdin\n")
	if err != nil || string(out) != "stdin\nliteral;$(shell)" || string(stderr) != "diagnostic" {
		t.Fatalf("direct command execution: out=%q stderr=%q err=%v", out, stderr, err)
	}
	for _, stream := range []string{"stdout", "stderr"} {
		out, stderr, err := runner.Run(ctx, program, []string{"-test.run=^TestCommandHelper$", "--", stream}, "")
		if err == nil || !strings.Contains(err.Error(), "1 MiB") || len(out) > maxOutput || len(stderr) > maxOutput {
			t.Fatalf("uncapped %s: stdout=%d stderr=%d error=%v", stream, len(out), len(stderr), err)
		}
	}
	short, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	start := time.Now()
	_, _, err = runner.Run(short, program, []string{"-test.run=^TestCommandHelper$", "--", "wait"}, "")
	if err == nil || !errors.Is(short.Err(), context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Fatalf("command ignored context deadline: %v", err)
	}
}

// Run only as a subprocess of TestExecRunner; no shell or nft is needed.
func TestCommandHelper(t *testing.T) {
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		return
	}
	switch args[0] {
	case "echo":
		if !reflect.DeepEqual(args, []string{"echo", "literal;$(shell)"}) {
			os.Exit(2)
		}
		_, _ = io.Copy(os.Stdout, os.Stdin)
		_, _ = fmt.Fprint(os.Stdout, args[1])
		_, _ = fmt.Fprint(os.Stderr, "diagnostic")
	case "stdout":
		_, _ = fmt.Fprint(os.Stdout, strings.Repeat("x", maxOutput+1))
	case "stderr":
		_, _ = fmt.Fprint(os.Stderr, strings.Repeat("x", maxOutput+1))
	case "wait":
		time.Sleep(commandTimeout)
	default:
		os.Exit(2)
	}
	os.Exit(0)
}
