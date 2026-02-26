//nolint:testpackage // testing internal methods
package resolver

import (
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/require"
)

func TestPodEntry(t *testing.T) {
	// Test the podInfo struct and its methods here
	namespace := "test-namespace"
	name := "test-name"
	policyName := "test-policy"
	labels := Labels{
		"test-label":            "test-value",
		v1alpha1.PolicyLabelKey: policyName,
	}

	podEntry := &podEntry{
		info: &podInfo{
			namespace: namespace,
			name:      name,
			labels:    labels,
		},
		containers: map[ContainerID]*containerInfo{
			"test-container": {
				cgID: CgroupID(12),
				name: "test-container-name",
			},
		},
	}

	require.Equal(t, name, podEntry.podName())
	require.Equal(t, namespace, podEntry.podNamespace())
	require.True(t, podEntry.matchPolicy(policyName, namespace))
	// same name but another namespace.
	require.False(t, podEntry.matchPolicy(policyName, "random-namespace"))
	// same namespace but different name.
	require.False(t, podEntry.matchPolicy("random-name", namespace))
}
