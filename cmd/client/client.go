package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Sudo-Ivan/reticulum-go/internal/config"
	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
	"github.com/Sudo-Ivan/reticulum-go/pkg/destination"
)

var (
	configPath = flag.String("config", "", "Path to config file")
	targetHash = flag.String("target", "", "Target destination hash")
)

func main() {
	flag.Parse()

	var cfg *common.ReticulumConfig
	var err error

	if *configPath == "" {
		cfg, err = config.InitConfig()
		if err != nil {
			log.Fatalf("Failed to initialize config: %v", err)
		}
	} else {
		cfg, err = config.LoadConfig(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
	}

	// Enable transport by default for client
	cfg.EnableTransport = true

	// Initialize transport
	transport, err := transport.NewTransport(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize transport: %v", err)
	}
	defer transport.Close()

	// If target specified, establish connection
	if *targetHash != "" {
		destHash, err := identity.HashFromHex(*targetHash)
		if err != nil {
			log.Fatalf("Invalid destination hash: %v", err)
		}

		// Request path if needed
		if !transport.HasPath(destHash) {
			fmt.Println("Requesting path to destination...")
			if err := transport.RequestPath(destHash, "", nil, true); err != nil {
				log.Fatalf("Failed to request path: %v", err)
			}
		}

		// Get destination identity
		destIdentity, err := identity.Recall(destHash)
		if err != nil {
			log.Fatalf("Failed to recall identity: %v", err)
		}

		// Create destination
		dest, err := destination.New(
			destIdentity,
			destination.OUT,
			destination.SINGLE,
			"client",
			"direct",
		)
		if err != nil {
			log.Fatalf("Failed to create destination: %v", err)
		}

		// Enable and configure ratchets
		dest.SetRetainedRatchets(destination.RATCHET_COUNT)
		dest.SetRatchetInterval(destination.RATCHET_INTERVAL)
		dest.EnforceRatchets()

		// Create link
		link := transport.NewLink(dest.Hash(), func() {
			fmt.Println("Link established")
		}, func() {
			fmt.Println("Link closed")
		})

		defer link.Teardown()

		// Set packet callback
		link.SetPacketCallback(func(data []byte) {
			fmt.Printf("Received: %s\n", string(data))
		})

		// Start interactive loop
		go interactiveLoop(link)
	} else {
		fmt.Println("No target specified. Use -target <hash> to connect to a destination")
		return
	}

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
}

func interactiveLoop(link *transport.Link) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading input: %v\n", err)
			continue
		}

		input = strings.TrimSpace(input)
		if input == "quit" || input == "exit" {
			return
		}

		if err := link.Send([]byte(input)); err != nil {
			fmt.Printf("Failed to send: %v\n", err)
		}
	}
} 