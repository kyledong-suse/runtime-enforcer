package controller

import (
	"context"
	"fmt"
	"time"

	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	agentClientTimeout = 5 * time.Second
)

// agentClientAPI this interface is used to mock the client in tests.
type agentClientAPI interface {
	listPoliciesStatus(ctx context.Context) (map[string]*pb.PolicyStatus, error)
	close() error
}

// This is the implementation used in the production code.
type agentClient struct {
	conn   *grpc.ClientConn
	client pb.AgentObserverClient
}

func newAgentClient(host string) (*agentClient, error) {
	conn, err := grpc.NewClient(host,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("grpc dial failed host %s: %w", host, err)
	}

	return &agentClient{
		conn:   conn,
		client: pb.NewAgentObserverClient(conn),
	}, nil
}

func (c *agentClient) listPoliciesStatus(ctx context.Context) (map[string]*pb.PolicyStatus, error) {
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, agentClientTimeout)
	defer timeoutCancel()

	resp, err := c.client.ListPoliciesStatus(timeoutCtx, &pb.ListPoliciesStatusRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetPolicies(), nil
}

func (c *agentClient) close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
