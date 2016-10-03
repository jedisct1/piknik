// +build !windows

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func handleSignals() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINFO)
	for {
		select {
		case signal, ok := <-signals:
			if !ok {
				break
			}
			switch signal {
			case syscall.SIGINT:
				os.Exit(128 + int(syscall.SIGINT))
			case syscall.SIGQUIT:
				os.Exit(128 + int(syscall.SIGQUIT))
			case syscall.SIGTERM:
				os.Exit(128 + int(syscall.SIGTERM))
			case syscall.SIGINFO:
				storedContent.RLock()
				procName := "piknik"
				if len(os.Args) >= 1 {
					procName = os.Args[0]
				}
				if storedContent.ts == nil {
					fmt.Printf("%v: the clipboard is empty\n", procName)
				} else {
					elapsed := time.Since(time.Unix(int64(binary.LittleEndian.Uint64(storedContent.ts)), 0))
					if elapsed <= 1 {
						fmt.Printf("%v: the clipboard is not empty (last filled a few moments ago)\n",
							procName)
					} else {
						fmt.Printf("%v: the clipboard is not empty (last filled %v minutes ago)\n",
							procName, elapsed)
					}
				}
				storedContent.RUnlock()
			}
		}
	}
}
