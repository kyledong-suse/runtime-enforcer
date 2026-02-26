package resolver

import "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"

// containerInfo is the internal representation of a container's information.
type containerInfo struct {
	cgID CgroupID
	name ContainerName
}

// podInfo is the internal representation of a pod's information.
type podInfo struct {
	podID        string
	namespace    string
	name         string
	workloadName string
	workloadType string
	labels       Labels
}

// podEntry is the internal representation of a pod inside our cache.
type podEntry struct {
	info       *podInfo
	containers map[ContainerID]*containerInfo
}

func (pod *podEntry) matchPolicy(policyName, policyNamespace string) bool {
	// now we need to check if the pod is in the same namespace of the policy since our policies are namespaced.
	return pod.policyName() == policyName && pod.podNamespace() == policyNamespace
}

func (pod *podEntry) policyName() string {
	return pod.info.labels[v1alpha1.PolicyLabelKey]
}

func (pod *podEntry) podName() string {
	return pod.info.name
}

func (pod *podEntry) podNamespace() string {
	return pod.info.namespace
}
