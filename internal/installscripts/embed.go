// Package installscripts holds the public installers. They contain no secrets.
package installscripts

import _ "embed"

//go:embed install.sh
var Shell []byte

//go:embed install.ps1
var PowerShell []byte
