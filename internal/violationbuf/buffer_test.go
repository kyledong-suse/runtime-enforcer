package violationbuf_test

import (
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/internal/violationbuf"
	"github.com/stretchr/testify/require"
)

func TestBufferRecordAndDrain(t *testing.T) {
	buf := violationbuf.NewBuffer()

	buf.Record(violationbuf.ViolationInfo{
		PolicyName:    "pol1",
		Namespace:     "ns1",
		PodName:       "pod1",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	})

	records := buf.Drain()
	require.Len(t, records, 1)
	require.Equal(t, "pol1", records[0].PolicyName)
	require.Equal(t, "ns1", records[0].Namespace)
	require.Equal(t, uint32(1), records[0].Count)

	// After drain, buffer should be empty.
	records = buf.Drain()
	require.Empty(t, records)
}

func TestBufferDeduplication(t *testing.T) {
	buf := violationbuf.NewBuffer()

	info := violationbuf.ViolationInfo{
		PolicyName:    "pol1",
		Namespace:     "ns1",
		PodName:       "pod1",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	}

	buf.Record(info)
	buf.Record(info)
	buf.Record(info)

	records := buf.Drain()
	require.Len(t, records, 1)
	require.Equal(t, uint32(3), records[0].Count)
}

func TestBufferDifferentKeys(t *testing.T) {
	buf := violationbuf.NewBuffer()

	buf.Record(violationbuf.ViolationInfo{
		PolicyName:    "pol1",
		Namespace:     "ns1",
		PodName:       "pod1",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	})

	buf.Record(violationbuf.ViolationInfo{
		PolicyName:    "pol1",
		Namespace:     "ns1",
		PodName:       "pod2",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	})

	records := buf.Drain()
	require.Len(t, records, 2)
}
