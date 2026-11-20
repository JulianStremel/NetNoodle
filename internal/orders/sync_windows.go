package orders

// Windows durability relies on the file sync and the directory ACL.
func syncParent(string) error { return nil }
