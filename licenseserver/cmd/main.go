package main

import (
	"flag"
	"log"

	"WoolCNC/licenseserver"
)

func main() {
	licenseDebug := flag.Bool("license_debug", false, "enable license debug logs")
	flag.Parse()
	licenseserver.Debug = *licenseDebug

	if err := licenseserver.InitDB("license.db"); err != nil {
		log.Fatalf("db init: %v", err)
	}
	if err := licenseserver.Start(":1234"); err != nil {
		log.Fatalf("server: %v", err)
	}
}
