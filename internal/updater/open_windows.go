package updater

import "os"

func openJSON(path string) (*os.File, error) { return os.Open(path) }
