// +build windows

package main

import (
	"os"
	"os/signal"
)

func handleSignals() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, os.Kill)

	for {
		select {
		case signal, ok := <-signals:
			if !ok {
				break
			}

			switch signal {
			case os.Interrupt, os.Kill:
				os.Exit(2)
			}
		}
	}
}
