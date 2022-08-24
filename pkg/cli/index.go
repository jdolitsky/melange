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

package cli

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	// nolint:gosec

	"github.com/spf13/cobra"
	apkrepo "gitlab.alpinelinux.org/alpine/go/pkg/repository"
)

func Index() *cobra.Command {
	var outDir string

	cmd := &cobra.Command{
		Use:     "index",
		Short:   "Generate an APK index",
		Long:    `Generate an APK index.`,
		Example: `  melange index`,
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return IndexCmd(cmd.Context(), outDir)
		},
	}

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	cmd.Flags().StringVar(&outDir, "out-dir", filepath.Join(cwd, "packages"), "directory where packages will be output")

	return cmd
}

func IndexCmd(ctx context.Context, outDir string) error {
	archs, err := os.ReadDir(outDir)
	if err != nil {
		return fmt.Errorf("failed to read packages directory %s: %w", outDir, err)
	}
	for _, arch := range archs {
		archName := arch.Name()
		if !arch.IsDir() {
			log.Printf("warning: found unknown file in packages directory: %s", archName)
			continue
		}
		log.Printf("generating APKINDEX.tar.gz for arch directory %s/", archName)
		archDir := filepath.Join(outDir, archName)
		apks, err := os.ReadDir(archDir)
		if err != nil {
			return fmt.Errorf("failed to read arch directory %s: %w", archDir, err)
		}
		packages := []*apkrepo.Package{}
		for _, apk := range apks {
			apkName := apk.Name()
			if apk.IsDir() || !strings.HasSuffix(apkName, ".apk") {
				log.Printf("warning: found unknown file in arch %s directory: %s", archName, apkName)
				continue
			}
			log.Printf("processing apk package %s/%s", archName, apkName)
			apkFilePath := filepath.Join(archDir, apkName)
			apkFile, err := os.Open(apkFilePath)
			if err != nil {
				return fmt.Errorf("failed to open apk package %s/%s: %w", archName, apkName, err)
			}
			pkg, err := apkrepo.ParsePackage(apkFile)
			if err != nil {
				return fmt.Errorf("failed to parse apk package %s/%s: %w", archName, apkName, err)
			}
			packages = append(packages, pkg)
		}
		index := &apkrepo.ApkIndex{
			Packages: packages,
		}
		archive, err := apkrepo.ArchiveFromIndex(index)
		if err != nil {
			return err
		}
		apkIndexFilename := filepath.Join(outDir, archName, "APKINDEX.tar.gz")
		outFile, err := os.Create(apkIndexFilename)
		if err != nil {
			return err
		}
		defer outFile.Close()
		if _, err = io.Copy(outFile, archive); err != nil {
			return err
		}
	}
	return nil
}
