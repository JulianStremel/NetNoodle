package store

import "context"

// Backuper is optional. Backup writes a consistent database snapshot to a new
// file. The destination must not exist. It never copies configuration secrets.
type Backuper interface {
	Backup(context.Context, string) error
}

// ExportBackuper writes a portable snapshot with integration credentials removed.
// Local recovery backups retain credentials.
type ExportBackuper interface {
	ExportBackup(context.Context, string) error
}
