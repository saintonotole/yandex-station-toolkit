package adb

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Official Android SDK Platform-Tools archives, see
// https://developer.android.com/tools/releases/platform-tools
const platformToolsURL = "https://dl.google.com/android/repository/platform-tools-latest-%s.zip"

const (
	platformToolsDir = "platform-tools"
	maxArchiveSize   = 256 << 20
)

func localBinary(dir string) string {
	name := "adb"
	if runtime.GOOS == "windows" {
		name = "adb.exe"
	}
	return filepath.Join(dir, platformToolsDir, name)
}

func DownloadURL() (string, error) {
	switch {
	case runtime.GOOS == "windows", runtime.GOOS == "darwin":
		return fmt.Sprintf(platformToolsURL, runtime.GOOS), nil
	case runtime.GOOS == "linux" && runtime.GOARCH == "amd64":
		return fmt.Sprintf(platformToolsURL, "linux"), nil
	}
	return "", fmt.Errorf("no official platform-tools build for %s/%s: install adb with the system package manager", runtime.GOOS, runtime.GOARCH)
}

func Download(ctx context.Context, dir string, log func(string)) (*Client, error) {
	if log == nil {
		log = func(string) {}
	}
	url, err := DownloadURL()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	archive, err := os.CreateTemp(dir, "platform-tools-*.zip")
	if err != nil {
		return nil, err
	}
	defer os.Remove(archive.Name())
	defer archive.Close()

	log("adb: downloading " + url)
	if err := fetch(ctx, url, archive); err != nil {
		return nil, err
	}

	staging, err := os.MkdirTemp(dir, "platform-tools-*.part")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(staging)
	if err := extract(archive.Name(), staging); err != nil {
		return nil, fmt.Errorf("adb: extract: %w", err)
	}
	if !fileExists(localBinary(staging)) {
		return nil, errors.New("adb: archive does not contain adb")
	}

	target := filepath.Join(dir, platformToolsDir)
	if err := os.RemoveAll(target); err != nil {
		return nil, err
	}
	if err := os.Rename(filepath.Join(staging, platformToolsDir), target); err != nil {
		return nil, err
	}
	p := localBinary(dir)
	log("adb: installed to " + p)
	return &Client{bin: p, own: true, log: log}, nil
}

func fetch(ctx context.Context, url string, w io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("adb: download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("adb: download: %s", resp.Status)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, maxArchiveSize+1))
	if err != nil {
		return fmt.Errorf("adb: download: %w", err)
	}
	if n > maxArchiveSize {
		return errors.New("adb: download: archive is too large")
	}
	return nil
}

func extract(archive, dst string) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		name := path.Clean(f.Name)
		if name != platformToolsDir && !strings.HasPrefix(name, platformToolsDir+"/") {
			continue
		}
		out := filepath.Join(dst, filepath.FromSlash(name))
		if !strings.HasPrefix(out, filepath.Clean(dst)+string(os.PathSeparator)) {
			return fmt.Errorf("unsafe path %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(out, 0o755); err != nil {
				return err
			}
			continue
		}
		if !f.Mode().IsRegular() {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		if err := writeEntry(f, out); err != nil {
			return err
		}
	}
	return nil
}

func writeEntry(f *zip.File, out string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	mode := f.Mode().Perm() | 0o600
	if path.Base(f.Name) == "adb" {
		mode |= 0o755
	}
	w, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, rc); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}
