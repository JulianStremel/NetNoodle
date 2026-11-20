package updater

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRunnerHelper(t *testing.T) {
	if os.Getenv("NN_UPDATER_TEST_HELPER") != "yes" {
		return
	}
	if os.Getenv("NN_UPDATER_TEST_SLEEP") == "yes" {
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
	fmt.Print(strings.Repeat("x", MaxJSON+100))
	os.Exit(0)
}
func TestExecRunnerTimeoutAndOutputCap(t *testing.T) {
	r := ExecRunner{Timeout: 10 * time.Second}
	out, e := r.Run(context.Background(), []string{"NN_UPDATER_TEST_HELPER=yes"}, os.Args[0], "-test.run=^TestRunnerHelper$")
	if e != nil || len(out) != MaxJSON {
		t.Fatal(len(out), e)
	}
	r.Timeout = 20 * time.Millisecond
	start := time.Now()
	_, e = r.Run(context.Background(), []string{"NN_UPDATER_TEST_HELPER=yes", "NN_UPDATER_TEST_SLEEP=yes"}, os.Args[0], "-test.run=^TestRunnerHelper$")
	if e == nil || time.Since(start) > 5*time.Second {
		t.Fatal("timeout not enforced", e)
	}
}
func TestSymlinkRequestRefused(t *testing.T) {
	u, r, req := fixture(t)
	target := u.Config.SharedDir + "/private.json"
	if e := os.WriteFile(target, []byte(`{"secret":"private"}`), 0600); e != nil {
		t.Fatal(e)
	}
	request := u.Config.SharedDir + "/requests/" + req.ID + ".json"
	if e := os.Remove(request); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(target, request); e != nil {
		t.Skip("symlink creation unavailable", e)
	}
	if e := u.RunOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
	s := readStatus(t, u, req.ID)
	if s.State != "rejected" || len(r.calls) != 0 {
		t.Fatal(s, r.calls)
	}
	b, e := os.ReadFile(target)
	if e != nil || !strings.Contains(string(b), "private") {
		t.Fatal("symlink target changed", e)
	}
}
