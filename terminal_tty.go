// +build darwin dragonfly freebsd linux,!appengine netbsd openbsd windows

package main

import "golang.org/x/crypto/ssh/terminal"

// IsTerminal - returns true if the file descriptor is attached to a terminal
func IsTerminal(fd int) bool {
	return terminal.IsTerminal(fd)
}
