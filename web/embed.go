// Package web embeds the static web UI (plain HTML, CSS and JavaScript,
// no build step).
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var files embed.FS

// FS returns the UI files with "static/" stripped.
func FS() fs.FS {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
