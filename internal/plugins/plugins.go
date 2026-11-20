// Package plugins links all built-in plug-ins into a program. Each plug-in
// registers itself in its registry in init(). To add a built-in plug-in,
// add one import line here.
package plugins

import (
	_ "github.com/JulianStremel/netnoodle/internal/intel/epss"
	_ "github.com/JulianStremel/netnoodle/internal/intel/kev"
	_ "github.com/JulianStremel/netnoodle/internal/intel/msrc"
	_ "github.com/JulianStremel/netnoodle/internal/intel/osv"
	_ "github.com/JulianStremel/netnoodle/internal/notify/webhook"
	_ "github.com/JulianStremel/netnoodle/internal/source/proxmox"
	_ "github.com/JulianStremel/netnoodle/internal/source/unifi"
)
