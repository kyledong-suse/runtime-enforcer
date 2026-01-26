package e2e_test

import (
	"slices"
	"time"
)

func waitForWorkloadPolicyStatusToBeUpdated() {
	// todo!: we should wait for the status of the WP to be updated, for now we just sleep a fixed time
	time.Sleep(5 * time.Second)
}

func verifyUbuntuLearnedProcesses(values []string) bool {
	return slices.Contains(values, "/usr/bin/bash") &&
		slices.Contains(values, "/usr/bin/ls") &&
		slices.Contains(values, "/usr/bin/sleep")
}
