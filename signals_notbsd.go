//go:build !darwin && !dragonfly && !freebsd && !netbsd && !openbsd
// +build !darwin,!dragonfly,!freebsd,!netbsd,!openbsd

package main

func handleSignals() {}
