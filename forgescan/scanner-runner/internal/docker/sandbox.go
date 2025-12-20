package docker

import (
	"context"
	"io"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
)

func RunContainer(
	ctx context.Context,
	cli *types.Client,
	image string,
	cmd []string,
	timeoutSeconds int64,
) (io.ReadCloser, error) {
	resp, err := cli.ContainerCreate(
		ctx,
		&container.Config{
			Image: image,
			Cmd:   cmd,
			User:  "1000:1000",
		},
		&SandboxLimits(),
		nil,
		nil,
		"",
	)
	if err != nil {
		return nil, err
	}

	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return nil, err
	}

	_, err = cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	if err != nil {
		return nil, err
	}

	return cli.ContainerLogs(ctx, resp.ID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
}
