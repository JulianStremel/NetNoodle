package updater

import "golang.org/x/sys/windows"

func freeSpace(path string) (uint64, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return 0, e
	}
	var n uint64
	e = windows.GetDiskFreeSpaceEx(p, &n, nil, nil)
	return n, e
}
