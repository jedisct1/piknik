//go:build (!darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows) || (linux && appengine)

package main

// IsTerminal - returns true if the file descriptor is attached to a terminal
func IsTerminal(fd int) bool {
	return false
}
