package updater

// ownedBySelf relies on the directory ACL on Windows (binary mode only).
func ownedBySelf(string) error { return nil }
