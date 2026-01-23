package nri

import (
	"context"
	"log/slog"
	"strings"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/neuvector/runtime-enforcer/internal/resolver"
	"github.com/neuvector/runtime-enforcer/internal/types/workloadkind"
)

type plugin struct {
	stub     stub.Stub
	logger   *slog.Logger
	resolver *resolver.Resolver
}

func (p *plugin) getWorkloadInfoAndLog(ctx context.Context, pod *api.PodSandbox) (string, workloadkind.Kind) {
	workloadName, workloadKind := getWorkloadInfo(pod)
	if strings.HasSuffix(workloadName, truncatedSuffix) {
		p.logger.WarnContext(ctx, "Detected truncated workload name",
			"name", workloadName,
			"kind", workloadKind,
			"pod", pod.GetName(),
		)
	}
	return workloadName, workloadKind
}

// Synchronize synchronizes the state of the NRI plugin with the current state of the pods and containers.
func (p *plugin) Synchronize(
	ctx context.Context,
	pods []*api.PodSandbox,
	containers []*api.Container,
) ([]*api.ContainerUpdate, error) {
	p.logger.InfoContext(ctx, "Synchronizing pod sandboxes", "podCount", len(pods))

	// we store the container for now and we associate them later with the pod sandbox
	tmpSandboxes := make(map[string]map[resolver.ContainerID]*resolver.ContainerData)
	for _, container := range containers {
		cgroupID, err := cgroupFromContainer(container)
		if err != nil {
			p.logger.ErrorContext(ctx, "failed to get cgroup ID from container",
				"error", err)
			continue
		}

		// Populate the sandbox map
		if _, exists := tmpSandboxes[container.GetPodSandboxId()]; !exists {
			tmpSandboxes[container.GetPodSandboxId()] = make(map[resolver.ContainerID]*resolver.ContainerData)
		}
		tmpSandboxes[container.GetPodSandboxId()][container.GetId()] = &resolver.ContainerData{
			CgID: cgroupID,
			Name: container.GetName(),
		}
	}

	for _, pod := range pods {
		if pod == nil {
			// safety check, this should never happen
			p.logger.ErrorContext(ctx, "received empty pod")
			continue
		}

		workloadName, workloadKind := p.getWorkloadInfoAndLog(ctx, pod)
		podData := &resolver.PodData{
			UID:       pod.GetId(),
			Name:      pod.GetName(),
			Namespace: pod.GetNamespace(),
			Labels:    pod.GetLabels(),
			// TODO!: we should try to extract the workload name/type from the pod annotations
			// this could be nil
			Containers:   tmpSandboxes[pod.GetId()],
			WorkloadName: workloadName,
			WorkloadType: string(workloadKind),
		}

		if err := p.resolver.AddPodContainerFromNri(podData); err != nil {
			p.logger.ErrorContext(ctx, "failed to add pod container from NRI",
				"error", err)
		}
	}
	return nil, nil
}

func (p *plugin) StartContainer(
	ctx context.Context,
	pod *api.PodSandbox,
	container *api.Container,
) error {
	cgroupID, err := cgroupFromContainer(container)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to get cgroup ID from container",
			"error", err)
	}

	workloadName, workloadKind := p.getWorkloadInfoAndLog(ctx, pod)
	podData := &resolver.PodData{
		UID:       pod.GetId(),
		Name:      pod.GetName(),
		Namespace: pod.GetNamespace(),
		Labels:    pod.GetLabels(),
		// TODO!: we should try to extract the workload name/type from the pod annotations
		// this could be nil
		Containers: map[resolver.ContainerID]*resolver.ContainerData{
			container.GetId(): {
				CgID: cgroupID,
				Name: container.GetName(),
			},
		},
		WorkloadName: workloadName,
		WorkloadType: string(workloadKind),
	}

	if err = p.resolver.AddPodContainerFromNri(podData); err != nil {
		p.logger.ErrorContext(ctx, "failed to add pod container from NRI",
			"error", err)
	}
	return nil
}

// RemoveContainer removes a container from the resolver when it is removed from the pod sandbox.
// The idea is that we want to keep the container alive in our cache as much as we can because ebpf asynchronously sends events,
// so it's possible that even if the container is stopped, we are still receiving some old events, and we want to enrich them.
// That's the reason why we preferred `RemoveContainer` over `StopContainer`.
func (p *plugin) RemoveContainer(ctx context.Context, pod *api.PodSandbox, container *api.Container) error {
	if err := p.resolver.RemovePodContainerFromNri(pod.GetId(), container.GetId()); err != nil {
		p.logger.ErrorContext(ctx, "failed to remove pod container from NRI",
			"error", err)
	}
	return nil
}
