package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/internal/config"
	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/destination"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/link"
	"github.com/Sudo-Ivan/reticulum-go/pkg/packet"
	"github.com/Sudo-Ivan/reticulum-go/pkg/resource"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
)

const (
	APP_NAME   = "example_utilities"
	APP_ASPECT = "filetransfer"
)

var (
	configPath = flag.String("config", "", "Path to config file")
	servePath  = flag.String("serve", "", "Directory to serve files from")
)

type FileServer struct {
	config     *common.ReticulumConfig
	transport  *transport.Transport
	interfaces []common.NetworkInterface
	identity   *identity.Identity
	servePath  string
}

func NewFileServer(cfg *common.ReticulumConfig, servePath string) (*FileServer, error) {
	if cfg == nil {
		var err error
		cfg, err = config.InitConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize config: %v", err)
		}
	}

	t, err := transport.NewTransport(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize transport: %v", err)
	}

	id, err := identity.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create identity: %v", err)
	}

	return &FileServer{
		config:     cfg,
		transport:  t,
		interfaces: make([]common.NetworkInterface, 0),
		identity:   id,
		servePath:  servePath,
	}, nil
}

func (s *FileServer) OnLinkEstablished(l *link.Link) {
	s.handleLinkEstablished(l)
}

func (s *FileServer) Start() error {
	dest, err := destination.New(
		s.identity,
		destination.OUT,
		destination.SINGLE,
		APP_NAME,
		APP_ASPECT,
	)
	if err != nil {
		return fmt.Errorf("failed to create destination: %v", err)
	}

	callback := func(l interface{}) {
		if link, ok := l.(*link.Link); ok {
			s.OnLinkEstablished(link)
		}
	}

	dest.SetLinkEstablishedCallback(callback)

	log.Printf("File server started. Server hash: %s", s.identity.Hex())
	log.Printf("Serving directory: %s", s.servePath)
	return nil
}

func (s *FileServer) handleLinkEstablished(l *link.Link) {
	log.Printf("Client connected")

	l.SetPacketCallback(func(data []byte, p *packet.Packet) {
		s.handlePacket(data, l)
	})

	l.SetResourceCallback(func(r interface{}) bool {
		if res, ok := r.(*resource.Resource); ok {
			return s.handleResource(res)
		}
		return false
	})
}

func (s *FileServer) handlePacket(data []byte, l *link.Link) {
	if string(data) == "LIST" {
		files, err := s.getFileList()
		if err != nil {
			log.Printf("Error getting file list: %v", err)
			l.Teardown()
			return
		}

		if err := l.SendPacket(files); err != nil {
			log.Printf("Error sending file list: %v", err)
			l.Teardown()
		}
	}
}

func (s *FileServer) handleResource(r *resource.Resource) bool {
	filename := filepath.Join(s.servePath, r.GetName())
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Failed to create file: %v", err)
		return false
	}
	defer file.Close()

	written, err := io.Copy(file, r)
	if err != nil {
		log.Printf("Failed to write file: %v", err)
		return false
	}

	log.Printf("Received file: %s (%d bytes)", filename, written)
	return true
}

func (s *FileServer) getFileList() ([]byte, error) {
	files, err := os.ReadDir(s.servePath)
	if err != nil {
		return nil, err
	}

	var fileList []string
	for _, file := range files {
		if !file.IsDir() {
			fileList = append(fileList, file.Name())
		}
	}

	return []byte(fmt.Sprintf("%v", fileList)), nil
}

func main() {
	flag.Parse()

	if *servePath == "" {
		log.Fatal("Please specify a directory to serve with -serve")
	}

	var cfg *common.ReticulumConfig
	var err error

	if *configPath == "" {
		cfg, err = config.InitConfig()
	} else {
		cfg, err = config.LoadConfig(*configPath)
	}
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	server, err := NewFileServer(cfg, *servePath)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	// Start watching the directory for changes
	go server.watchDirectory()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
}

func (s *FileServer) watchDirectory() {
	for {
		time.Sleep(1 * time.Second)
		files, err := os.ReadDir(s.servePath)
		if err != nil {
			log.Printf("Error reading directory: %v", err)
			continue
		}

		for _, file := range files {
			if !file.IsDir() {
				// Try to send file to connected peers
				filePath := filepath.Join(s.servePath, file.Name())
				if err := s.sendFile(filePath); err != nil {
					log.Printf("Error sending file %s: %v", file.Name(), err)
				}
			}
		}
	}
}

func (s *FileServer) sendFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Create a destination for the file transfer
	dest, err := destination.New(
		s.identity,
		destination.OUT,
		destination.SINGLE,
		APP_NAME,
		APP_ASPECT,
	)
	if err != nil {
		return fmt.Errorf("failed to create destination: %v", err)
	}

	// Set up link for file transfer
	callback := func(l interface{}) {
		if link, ok := l.(*link.Link); ok {
			// Create a new resource with auto-compression enabled
			res, err := resource.New(file, true)
			if err != nil {
				log.Printf("Error creating resource: %v", err)
				return
			}

			// The filename is automatically set from the file handle
			// in resource.New when using an io.ReadWriteSeeker

			// Send the resource through the link
			if err := link.SendResource(res); err != nil {
				log.Printf("Error sending resource: %v", err)
				return
			}
			log.Printf("File %s sent successfully", filepath.Base(filePath))
		}
	}

	dest.SetLinkEstablishedCallback(callback)

	return nil
}
