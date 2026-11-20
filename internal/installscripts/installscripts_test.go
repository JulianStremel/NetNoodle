package installscripts

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func shell(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is not installed")
	}
	return path
}
func runShell(t *testing.T, script string, env ...string) string {
	t.Helper()
	file, err := filepath.Abs("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(shell(t), "-c", script, "test", filepath.ToSlash(file))
	cmd.Env = append(os.Environ(), append([]string{"NN_INSTALL_LIBRARY=1"}, env...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shell: %v\n%s", err, out)
	}
	return string(out)
}
func TestShellSyntax(t *testing.T) {
	out, err := exec.Command(shell(t), "-n", "install.sh").CombinedOutput()
	if err != nil {
		t.Fatalf("syntax: %v\n%s", err, out)
	}
}
func TestSetupCodeParse(t *testing.T) {
	fields := "server=https://10.0.0.5:7443\nfingerprint=" + strings.Repeat("a", 64) + "\nspki=" + strings.Repeat("A", 43) + "=\nsession=0123456789abcdef\nsecret=" + strings.Repeat("s", 43) + "\ntoken=join-token\nname=web01\nkind=agent\nversion=v0.1.0\nexpires=2099-01-01T00:00:00Z\nfuture=ignored\n"
	code := func(text string) string { return "nnsetup1:" + base64.RawURLEncoding.EncodeToString([]byte(text)) }
	out := runShell(t, `. "$1"; parse_code "$CODE"; [ "$name" = web01 ]; [ "$server" = https://10.0.0.5:7443 ]; [ "$spki" = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' ]; printf ok`, "CODE="+code(fields))
	if out != "ok" {
		t.Fatalf("parse: %q", out)
	}
	for _, invalid := range []string{"nnsetup1:!", code(strings.ReplaceAll(fields, "name=web01\n", "")), code(fields + "name=duplicate\n"), code(strings.ReplaceAll(fields, "name=web01", "name=$(touch /tmp/nn-injection)")), code(strings.ReplaceAll(fields, "server=https://10.0.0.5:7443", "server=https://host';id;#"))} {
		runShell(t, `. "$1"; if parse_code "$CODE"; then exit 1; fi`, "CODE="+invalid)
	}
}
func TestRollbackJournal(t *testing.T) {
	shell(t)
	root := t.TempDir()
	fake := filepath.Join(root, "fake")
	if err := os.Mkdir(fake, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"systemctl", "useradd", "userdel", "id"} {
		body := "#!/bin/sh\nprintf '%s\\n' \"" + name + " $*\" >> \"$CALLS\"\n"
		if name == "id" {
			body += "exit 0\n"
		}
		if err := os.WriteFile(filepath.Join(fake, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	root = filepath.ToSlash(root)
	fake = filepath.ToSlash(fake)
	script := `. "$1"
install_root=$ROOT/install; unit_root=$ROOT/units; journal=$ROOT/install/web01.journal
mkdir "$install_root" "$unit_root"
: > "$journal"
make_dir "$install_root/web01"
record user nni-test
useradd nni-test
make_file "$install_root/web01/config"
printf data > "$install_root/web01/config"
# The service can make runtime files after installation.
printf state > "$install_root/web01/runtime"
make_file "$unit_root/nn-web01.service"
printf unit > "$unit_root/nn-web01.service"
record unit nn-web01.service
rollback
[ ! -e "$journal" ] && [ ! -e "$install_root/web01" ] && [ ! -e "$unit_root/nn-web01.service" ]
`
	runShell(t, script, "ROOT="+root, "CALLS="+root+"/calls", "PATH="+fake+string(os.PathListSeparator)+os.Getenv("PATH"))
	b, err := os.ReadFile(filepath.FromSlash(root + "/calls"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{"useradd nni-test", "systemctl stop nn-web01.service", "systemctl disable nn-web01.service", "userdel nni-test", "systemctl daemon-reload"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s:\n%s", want, got)
		}
	}
	if strings.Index(got, "systemctl stop") > strings.Index(got, "userdel") {
		t.Fatalf("wrong rollback order:\n%s", got)
	}
}

func TestDownloadFailureAbortsWithoutRemovingExistingInstall(t *testing.T) {
	root := filepath.ToSlash(t.TempDir())
	out := runShell(t, `. "$1"
work=$ROOT/work; mkdir "$work"
journal=$ROOT/existing.journal; printf 'existing install\n' > "$journal"
armed=1; success=0; journal_active=0; stage=download
secret=must-not-be-printed; token=must-not-be-printed
session_call() { printf '%s %s\n' "$1" "$2" >> "$ROOT/calls"; }
set +e
(trap cleanup EXIT; exit 7)
rc=$?
set -e
[ "$rc" -eq 7 ]
[ -f "$journal" ] && [ ! -e "$work" ]
[ "$(cat "$ROOT/calls")" = 'POST /step
POST /abort' ]
printf ok`, "ROOT="+root)
	if strings.Contains(out, "must-not-be-printed") || !strings.HasSuffix(out, "ok") {
		t.Fatalf("failure cleanup: %s", out)
	}
}

func TestRollbackFailureKeepsJournalAndAborts(t *testing.T) {
	root := filepath.ToSlash(t.TempDir())
	out := runShell(t, `. "$1"
work=$ROOT/work; mkdir "$work"
install_root=$ROOT/install; unit_root=$ROOT/units
journal=$ROOT/failed.journal
printf 'file|/outside-the-install-root\n' > "$journal"
armed=1; success=0; journal_active=1; stage=service
secret=must-not-be-printed
systemctl() { return 0; }
session_call() { printf '%s %s\n' "$1" "$2" >> "$ROOT/calls"; }
set +e
(trap cleanup EXIT; exit 9)
rc=$?
set -e
[ "$rc" -ne 0 ] && [ -f "$journal" ]
grep -q '^POST /abort$' "$ROOT/calls"
printf ok`, "ROOT="+root)
	if !strings.Contains(out, "Rollback had errors") || strings.Contains(out, "must-not-be-printed") {
		t.Fatalf("rollback errors were hidden or leaked a secret: %s", out)
	}
}

func TestPowerShellSyntax(t *testing.T) {
	path := ""
	for _, name := range []string{"pwsh", "powershell"} {
		if p, err := exec.LookPath(name); err == nil {
			path = p
			break
		}
	}
	if path == "" {
		t.Skip("PowerShell is not installed")
	}
	// A binary on PATH may still be unusable (for example, a sandbox can
	// prevent the PowerShell host from initializing). Probe separately so a
	// real parser error below is never mistaken for an unavailable runtime.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, path, "-NoProfile", "-NonInteractive", "-Command", "exit 0").CombinedOutput(); err != nil {
		t.Skipf("PowerShell cannot run: %v (%s)", err, out)
	}
	file, err := filepath.Abs("install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	command := fmt.Sprintf(`$tokens=$null; $errors=$null; [System.Management.Automation.Language.Parser]::ParseFile('%s',[ref]$tokens,[ref]$errors) | Out-Null; if ($errors.Count) { $errors | Out-String | Write-Output; exit 1 }`, strings.ReplaceAll(file, "'", "''"))
	out, err := exec.Command(path, "-NoProfile", "-NonInteractive", "-Command", command).CombinedOutput()
	if err != nil {
		t.Fatalf("syntax: %v\n%s", err, out)
	}
}
