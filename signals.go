// +build !windows 

package main

import(
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func handleSignals() {
        signals := make(chan os.Signal, 1)
        signal.Notify(signals, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGUSR1)

	for {
		select {
		case signal, ok := <-signals:
			if !ok { break }

			switch(signal) {
			case syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM:
				os.Exit(2)
			case syscall.SIGUSR1:
				if len(storedContent.ciphertextWithNonce) > 0 {
					fmt.Printf("%v: some data is stored\n", os.Args[0])
				} else {
					fmt.Printf("%v: no data stored yet\n", os.Args[0])
				}
			}
		}
	}
}
