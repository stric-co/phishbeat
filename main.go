package main

import (
	"os"
	"github.com/stric-co/phishbeat/cmd"
	_ "github.com/stric-co/phishbeat/include"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
