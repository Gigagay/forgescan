package docker

import "github.com/docker/docker/api/types/container"

func SandboxLimits() container.HostConfig {
	return container.HostConfig{
		ReadonlyRootfs: true,
		AutoRemove:     true,
		CapDrop:        []string{"ALL"},
		Resources: container.Resources{
			Memory:    512 * 1024 * 1024,
			NanoCPUs:  1_000_000_000,
			PidsLimit: func() *int64 { v := int64(64); return &v }(),
		},
		NetworkMode: "bridge",
	}
}
