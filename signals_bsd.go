//go:build darwin || dragonfly || freebsd || netbsd || openbsd
// +build darwin dragonfly freebsd netbsd openbsd

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
	signal.Notify(signals, syscall.SIGINFO)
	for {
		signal, ok := <-signals
		if !ok {
			break
		}
		switch signal {
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
				if elapsed <= time.Minute {
					fmt.Printf("%v: the clipboard is not empty (last filled a few moments ago)\n",
						procName)
				} else {
					fmt.Printf("%v: the clipboard is not empty (last filled %v ago)\n",
						procName, elapsed)
				}
			}
			storedContent.RUnlock()
		}
	}
}
