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
	"bytes"
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
			Packages:    packages,
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
			cfg, err := ini.ShadowLoad(tarRead)
			if err != nil {
				return nil, fmt.Errorf("Fail to read file: %w", err)
			}
			apkInfo := new(APKInfo)
			err = cfg.MapTo(apkInfo)
			if err != nil {
				return nil, err
			}
			checksum, err := getChecksum(apkFilePath)
			if err != nil {
				return nil, err
			}
			return &apkrepo.Package{
				Name:             apkInfo.PKGName,
				Version:          apkInfo.PKGVer,
				Arch:             apkInfo.Arch,
				Description:      apkInfo.PKGDesc,
				License:          apkInfo.License,
				Origin:           apkInfo.Origin,
				Maintainer:       apkInfo.Maintainer,
				URL:              apkInfo.URL,
				Checksum:         checksum,
				Dependencies:     apkInfo.Depend,
				Provides:         apkInfo.Provides,
				Size:             uint64(fileInfo.Size()),
				InstalledSize:    uint64(apkInfo.Size),
				RepoCommit:       apkInfo.Commit,
			}, nil
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


func getChecksum(apkFilePath string) ([]byte, error) {
	file, err := os.Open(apkFilePath)
	if err != nil {
		return nil, err
	}
	streams, _, err := createPackageStreams(file)
	if err != nil {
		return nil, err
	}
	fmt.Println("Num streams: "+string(len(streams)))
	hasher := sha1.New()
	data, err := ioutil.ReadFile(streams[0])
	if err != nil {
		return nil, err
	}
	if _, err := hasher.Write(data); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

type chapter struct {
	begin int64
	end   int64
}

func createPackageStreams(source io.Reader) ([]string, string, error) {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		return []string{}, dir, err
	}

	indata, err := ioutil.ReadAll(source)
	if err != nil {
		return []string{}, dir, err
	}

	bio := bytes.NewReader(indata)

	gzi, err := gzip.NewReader(bio)
	if err != nil {
		return []string{}, dir, err
	}

	i := 0
	chapters := []chapter{}

	for {
		gzi.Multistream(true)

		pos, err := bio.Seek(0, os.SEEK_CUR)
		if err != nil {
			return []string{}, dir, err
		}

		chapter := chapter{
			begin: pos - 10,
			end:   int64(bio.Len()),
		}

		log.Printf("new stream! id=%d @%d", i, pos)
		if i > 0 {
			chapters[i-1].end = pos - 10
		}

		chapters = append(chapters, chapter)

		outF, err := os.Create(fmt.Sprintf("%s/stream-%d.tar", dir, i))
		if err != nil {
			return []string{}, dir, err
		}
		defer outF.Close()

		if _, err := io.Copy(outF, gzi); err != nil {
			log.Printf("failed while copying")
			return []string{}, dir, err
		}

		i++

		err = gzi.Reset(bio)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("failed while resetting")
			return []string{}, dir, err
		}
	}

	if err := gzi.Close(); err != nil {
		log.Fatal(err)
	}

	var fileStreams []string
	for i, chapter := range chapters {
		log.Printf("chapter %d, begin: %d, end: %d", i, chapter.begin, chapter.end)

		fileName := fmt.Sprintf("%s/stream-%d.tar.gz", dir, i)
		outF, err := os.Create(fileName)
		if err != nil {
			return []string{}, dir, err
		}
		defer outF.Close()

		_, _ = outF.Write(indata[chapter.begin:chapter.end])
		fileStreams = append(fileStreams, fileName)
	}

	return fileStreams, dir, err
}
