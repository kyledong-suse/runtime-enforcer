package workloadkind

type Kind string

const (
	Pod         Kind = "Pod"
	Deployment  Kind = "Deployment"
	DaemonSet   Kind = "DaemonSet"
	StatefulSet Kind = "StatefulSet"
	ReplicaSet  Kind = "ReplicaSet"
	Job         Kind = "Job"
	CronJob     Kind = "CronJob"
	Unknown     Kind = "Unknown"
)

func (k Kind) String() string { return string(k) }
