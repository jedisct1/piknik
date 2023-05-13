//go:build darwin || dragonfly || freebsd || (linux && !appengine) || netbsd || openbsd || windows
// +build darwin dragonfly freebsd linux,!appengine netbsd openbsd windows

package main

import "golang.org/x/term"

// IsTerminal - returns true if the file descriptor is attached to a terminal
func IsTerminal(fd int) bool {
	return term.IsTerminal(fd)
}
