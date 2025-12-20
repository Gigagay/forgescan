package docker

import (
	"context"

	"github.com/docker/docker/client"
)

func New() (*client.Client, error) {
	return client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
}

func Ctx() context.Context {
	return context.Background()
}
