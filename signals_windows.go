// +build windows

package main

import (
	"os"
	"os/signal"
)

func handleSignals() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Kill)
	for {
		select {
		case signal, ok := <-signals:
			if !ok {
				break
			}
			switch signal {
			case os.Kill:
				os.Exit(128 + 15)
			}
		}
	}
}
