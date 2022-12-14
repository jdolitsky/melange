package build

import (
	"chainguard.dev/melange/pkg/container"
)

type runner string

const (
	runnerBubblewrap runner = "bubblewrap"
	runnerDocker     runner = "docker"
	runnerLima       runner = "lima"
	// more to come
)

// GetRunner gets a runner from a string.
// If an unknown runner, returns an error.
func GetRunner(s string) (container.Runner, error) {
	return container.GetRunner(s)
}

// GetDefaultRunner returns the default runner to use.
// Currently, this is bubblewrap, but will be replaced with determining by platform.
func GetDefaultRunner() runner {
	return runnerBubblewrap
}

// GetAllrunners returns a list of all valid runners.
func GetAllRunners() []runner {
	return []runner{
		runnerBubblewrap,
		runnerDocker,
		runnerLima,
	}
}
