// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"cottendns-go/internal/client"
	"cottendns-go/internal/config"
	"cottendns-go/internal/runtimepath"
	"cottendns-go/internal/version"
)

func waitForExitInput() {
	_, _ = fmt.Fprint(os.Stderr, "Press Enter to exit...")
	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
}

func main() {
	configPath := flag.String("config", "client_config.toml", "Path to client configuration file")
	resolversPath := flag.String("resolvers", "", "Path to resolver file override (optional)")
	scanOnly := flag.Bool("scan-only", false, "Scan resolvers, emit WD_SCAN results, and exit without starting the tunnel")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	configFlags, err := config.NewClientConfigFlagBinder(flag.CommandLine)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Client flag setup failed: %v\n", err)
		os.Exit(2)
	}
	flag.Parse()

	if *versionFlag {
		fmt.Printf("CottenDns Client Version: %s\n", version.GetVersion())
		return
	}

	resolvedConfigPath := runtimepath.Resolve(*configPath)
	overrides := configFlags.Overrides()
	if *resolversPath != "" {
		resolvedResolversPath := runtimepath.Resolve(*resolversPath)
		overrides.ResolversFilePath = &resolvedResolversPath
	}

	// Resolver conditions change too quickly on the target networks to trust a
	// previous-run cache. Every process start builds from the current resolver
	// source and performs fresh authenticated MTU/path validation.
	app, err := client.Bootstrap(resolvedConfigPath, overrides)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Client startup failed: %v\n", err)
		if !*scanOnly {
			waitForExitInput()
		}
		os.Exit(1)
	}

	if *scanOnly {
		sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if _, err := app.RunResolverScan(sigCtx); err != nil {
			fmt.Fprintf(os.Stderr, "Resolver scan failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	app.PrintBanner()

	log := app.Log()
	if log != nil {
		log.Infof("\U0001F680 <green>CottenDns Client Started</green>")
		log.Infof("\U0001F4C4 <green>Configuration loaded from: <cyan>%s</cyan></green>", resolvedConfigPath)
		log.Infof("\U0001F5C2  <green>Connection Catalog: <cyan>%d</cyan> domain-resolver pairs</green>", len(app.Connections()))
	}

	// Wait for termination signal
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := app.Run(sigCtx); err != nil {
		if log != nil {
			log.Errorf("Runtime error: %v", err)
		}
	}

	if log != nil {
		log.Infof("\U0001F6D1 <red>Shutting down...</red>")
	}
}
