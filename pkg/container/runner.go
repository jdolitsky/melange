// Copyright 2022 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package container

import (
	"fmt"
	"os/exec"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/google/go-containerregistry/pkg/name"
)

type Runner interface {
	TestUsability() bool
	// OCIImageLoader returns a Loader that will load an OCI image from a stream.
	// If the specific Runner does not need one, it should return nil, in which case the filesystem layout is bind-mounted
	// to / in the container.
	// If the specific Runner does need one, it should return the Loader, which will be used to load the provided image
	// as a tar stream into the Loader. That image will be used as the root when StartPod() the container.
	OCIImageLoader() Loader
	StartPod(cfg *Config) error
	Run(cfg *Config, cmd ...string) error
	TerminatePod(cfg *Config) error
	// TempDir returns the base for temporary directory, or "" if whatever is provided by the system is fine
	TempDir() string
}

type Loader interface {
	LoadImage(layerTarGZ string, arch apko_types.Architecture, bc *apko_build.Context) (hash name.Digest, err error)
}

// GetRunner returns the requested runner implementation.
func GetRunner(s string) (Runner, error) {
	switch s {
	case "bubblewrap":
		return BubblewrapRunner(), nil
	case "docker":
		return DockerRunner(), nil
	case "lima":
		return LimaRunner()
	}
	return nil, fmt.Errorf("unknown virtualizer %q", s)
}

// monitorCmd sets up the stdout/stderr pipes and then supervises
// execution of an exec.Cmd.
func monitorCmd(cfg *Config, cmd *exec.Cmd) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	finishStdout := make(chan struct{})
	finishStderr := make(chan struct{})

	go monitorPipe(cfg.Logger, stdout, finishStdout)
	go monitorPipe(cfg.Logger, stderr, finishStderr)

	if err := cmd.Wait(); err != nil {
		return err
	}

	<-finishStdout
	<-finishStderr

	return nil
}
