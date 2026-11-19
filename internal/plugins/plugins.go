// Package plugins links all built-in plug-ins into a program. Each plug-in
// registers itself in its registry in init(). To add a built-in plug-in,
// add one import line here.
package plugins

import (
	_ "netnoodle/internal/notify/webhook"
	_ "netnoodle/internal/source/unifi"
)
