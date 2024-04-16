package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/nermius/nermius/internal/cli"
)

type exitCoder interface {
	ExitCode() int
}

func main() {
	if err := cli.Execute(); err != nil {
		var codeErr exitCoder
		if errors.As(err, &codeErr) {
			if message := err.Error(); message != "" {
				fmt.Fprintln(os.Stderr, message)
			}
			os.Exit(codeErr.ExitCode())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
