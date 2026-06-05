package main

import (
	"os"

	"github.com/whitedns/wdns-wizard/internal/cli"
)

func main() {
	if err := cli.NewRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
