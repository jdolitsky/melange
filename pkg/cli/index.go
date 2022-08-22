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
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	// nolint:gosec

	"github.com/spf13/cobra"
	apkrepo "gitlab.alpinelinux.org/alpine/go/pkg/repository"
	"gopkg.in/ini.v1"
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
			pkg, err := parseApk(apkFilePath)
			if err != nil {
				return fmt.Errorf("failed to parse apk package %s/%s: %w", archName, apkName, err)
			}
			packages = append(packages, pkg)
		}

		index := &apkrepo.ApkIndex{
			//Signature:   nil,
			//Description: "hello nice to meet u",
			Packages:    packages,
		}

		archive, err := apkrepo.ArchiveFromIndex(index)

		apkIndexFilename := filepath.Join(outDir, archName, "APKINDEX.tar.gz")
		outFile, err := os.Create(apkIndexFilename)
		defer outFile.Close()
		if _, err = io.Copy(outFile, archive); err != nil {
			return err
		}
	}
	return nil
}


// TODO: upstream this in gitlab
// From https://github.com/chainguard-dev/apk-repo-generator/blob/5666d7fbe6ac891527d8995f13863b7ec4127def/main.go#L509
func parseApk(apkFilePath string) (*apkrepo.Package, error) {
	file, err := os.Open(apkFilePath)
	if err != nil {
		return nil, err
	}
	fileInfo, err := os.Lstat(apkFilePath)
	if err != nil {
		return nil, err
	}
	gzRead, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	tarRead := tar.NewReader(gzRead)
	for {
		cur, err := tarRead.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if cur.Typeflag != tar.TypeReg {
			continue
		}
		if cur.Name == ".PKGINFO" {
			// load the config
			cfg, err := ini.ShadowLoad(tarRead)
			if err != nil {
				return nil, fmt.Errorf("Fail to read file: %w", err)
			}
			apkInfo := new(APKInfo)
			err = cfg.MapTo(apkInfo)
			if err != nil {
				return nil, err
			}

			// generate the sha1 for the apk ID
			hasher := sha1.New()
			data, err := ioutil.ReadFile(apkFilePath)
			if err != nil {
				return nil, err
			}
			hasher.Write(data)

			idRaw := hasher.Sum(nil)
			//apkInfo.ID = fmt.Sprintf("Q1%s", b64.StdEncoding.Encode(hasher.Sum(nil)))
			log.Println(">>>", string(idRaw))

			/*
			var buildTime time.Time
			if apkInfo.BuildDate != "" {
				buildTime, err = time.Parse("2022/08/19 22:42:41", apkInfo.BuildDate)
				if err != nil {
					return nil, err
				}
			}
			*/

			//buildTime := time.Now()

			apkInfoUpstream := &apkrepo.Package{
				Name:             apkInfo.PKGName,
				Version:          apkInfo.PKGVer,
				Arch:             apkInfo.Arch,
				Description:      apkInfo.PKGDesc,
				License:          apkInfo.License,
				Origin:           apkInfo.Origin,
				Maintainer:       apkInfo.Maintainer,
				URL:              apkInfo.URL,
				Checksum:         idRaw,
				Dependencies:     apkInfo.Depend,
				Provides:         apkInfo.Provides,
				//InstallIf:        strings.Split(apkInfo.InstallIf, " "),
				Size:             uint64(fileInfo.Size()),
				InstalledSize:    uint64(apkInfo.Size),
				//ProviderPriority: 0,
				//BuildTime:        buildTime,
				RepoCommit:       apkInfo.Commit,
				//Replaces:         "",
			}

			return apkInfoUpstream, nil
		}
	}
	return nil, fmt.Errorf("unknown error")
}

// TODO: remove / upstream to gitlab
type APKInfo struct {
	ID         string
	PKGName    string   `ini:"pkgname"`
	PKGVer     string   `ini:"pkgver"`
	PKGDesc    string   `ini:"pkgdesc"`
	URL        string   `ini:"url"`
	BuildDate  string   `ini:"builddate"`
	Packager   string   `ini:"packager"`
	Size       int      `ini:"size"`
	Arch       string   `ini:"arch"`
	Origin     string   `ini:"origin"`
	Commit     string   `ini:"commit"`
	Maintainer string   `ini:"maintainer"`
	License    string   `ini:"license"`
	InstallIf  string   `ini:"install_if"`
	Datahash   string   `ini:"datahash"`
	Depend     []string `ini:"depend,,allowshadow"`
	Provides   []string `ini:"provides,,allowshadow"`
}
