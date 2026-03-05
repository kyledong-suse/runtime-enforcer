package violationbuf

import (
	"sync"
	"time"
)

// ViolationInfo contains the details of a single policy violation event.
type ViolationInfo struct {
	PolicyName    string
	Namespace     string
	PodName       string
	ContainerName string
	ExePath       string
	NodeName      string
	Action        string
}

// ViolationRecord is a violation record ready for scraping.
type ViolationRecord struct {
	Timestamp     time.Time
	PolicyName    string
	Namespace     string
	PodName       string
	ContainerName string
	ExePath       string
	NodeName      string
	Action        string
}

// MaxBufferEntries is the capacity of the ring buffer. When full, the oldest
// entry is overwritten.
const MaxBufferEntries = 10_000

// Buffer is a thread-safe ring buffer for violation records.
// The EventScraper calls Record() for each violation; the gRPC server calls
// Drain() when the controller scrapes.
type Buffer struct {
	mtx  sync.Mutex
	buf  []ViolationRecord
	head int
	tail int
	full bool
}

// NewBuffer creates a new violation buffer.
func NewBuffer() *Buffer {
	return &Buffer{
		buf: make([]ViolationRecord, MaxBufferEntries),
	}
}

// Record appends a violation to the ring buffer. If the buffer is full,
// the oldest entry is overwritten.
func (b *Buffer) Record(info ViolationInfo) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.buf[b.head] = ViolationRecord{
		Timestamp:     time.Now(),
		PolicyName:    info.PolicyName,
		Namespace:     info.Namespace,
		PodName:       info.PodName,
		ContainerName: info.ContainerName,
		ExePath:       info.ExePath,
		NodeName:      info.NodeName,
		Action:        info.Action,
	}

	b.head = (b.head + 1) % MaxBufferEntries
	if b.full {
		b.tail = b.head
	}
	if b.head == b.tail {
		b.full = true
	}
}

// Drain returns all buffered records in reverse chronological order (newest first)
// and resets the buffer.
func (b *Buffer) Drain() []ViolationRecord {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	n := b.len()
	if n == 0 {
		return nil
	}

	records := make([]ViolationRecord, 0, n)
	for i := range n {
		idx := (b.head - 1 - i + MaxBufferEntries) % MaxBufferEntries
		records = append(records, b.buf[idx])
	}

	b.head = 0
	b.tail = 0
	b.full = false

	return records
}

// len returns the number of entries in the ring buffer (caller must hold mtx).
func (b *Buffer) len() int {
	if b.full {
		return MaxBufferEntries
	}
	return (b.head - b.tail + MaxBufferEntries) % MaxBufferEntries
}
