package crypto

import (
	"runtime"
)

// SecureBytes is a byte slice that will be zeroed out when it's no longer needed.
type SecureBytes struct {
	bytes []byte
}

// NewSecureBytes creates a new SecureBytes instance.
func NewSecureBytes(b []byte) *SecureBytes {
	// Make a copy to avoid sharing the underlying array
	copied := make([]byte, len(b))
	copy(copied, b)
	s := &SecureBytes{bytes: copied}
	runtime.SetFinalizer(s, func(s *SecureBytes) {
		s.Zero()
	})
	return s
}

// Bytes returns the raw byte slice.
func (s *SecureBytes) Bytes() []byte {
	return s.bytes
}

// Zero clears the bytes from memory.
func (s *SecureBytes) Zero() {
	if s.bytes == nil {
		return
	}
	// This is a best-effort attempt to clear the memory.
	// In Go, this isn't guaranteed due to GC and memory management.
	for i := range s.bytes {
		s.bytes[i] = 0
	}
	s.bytes = nil
}
