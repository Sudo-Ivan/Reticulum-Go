package transport

import (
	"crypto/rand"
	"testing"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic("Failed to generate random bytes: " + err.Error())
	}
	return b
}

// BenchmarkTransportDestinationCreation benchmarks destination creation
func BenchmarkTransportDestinationCreation(b *testing.B) {
	// Create a basic config for transport
	config := &common.ReticulumConfig{
		ConfigPath: "/tmp/test_config",
	}

	transport := NewTransport(config)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Create destination (this allocates and initializes destination objects)
		dest := transport.NewDestination(nil, OUT, SINGLE, "test_app")
		_ = dest // Use the destination to avoid optimization
	}
}

// BenchmarkTransportPathLookup benchmarks path lookup operations
func BenchmarkTransportPathLookup(b *testing.B) {
	// Create a basic config for transport
	config := &common.ReticulumConfig{
		ConfigPath: "/tmp/test_config",
	}

	transport := NewTransport(config)

	// Pre-populate with some destinations
	destHash1 := randomBytes(16)
	destHash2 := randomBytes(16)
	destHash3 := randomBytes(16)

	// Create some destinations
	transport.NewDestination(nil, OUT, SINGLE, "test_app")
	transport.NewDestination(nil, OUT, SINGLE, "test_app")
	transport.NewDestination(nil, OUT, SINGLE, "test_app")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Test path lookup operations (these involve map lookups and allocations)
		_ = transport.HasPath(destHash1)
		_ = transport.HasPath(destHash2)
		_ = transport.HasPath(destHash3)
	}
}

// BenchmarkTransportHopsCalculation benchmarks hops calculation
func BenchmarkTransportHopsCalculation(b *testing.B) {
	// Create a basic config for transport
	config := &common.ReticulumConfig{
		ConfigPath: "/tmp/test_config",
	}

	transport := NewTransport(config)

	// Create some destinations
	destHash := randomBytes(16)
	transport.NewDestination(nil, OUT, SINGLE, "test_app")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Test hops calculation (involves internal data structure access)
		_ = transport.HopsTo(destHash)
	}
}
