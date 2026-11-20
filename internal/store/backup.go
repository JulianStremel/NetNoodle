package store

import "context"

// Backuper is optional. Backup writes a consistent database snapshot to a new
// file. The destination must not exist. It never copies configuration secrets.
type Backuper interface {
	Backup(context.Context, string) error
}
