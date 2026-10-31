package adb

import (
	"archive/zip"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func writeZip(t *testing.T, entries map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pt.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func adbName() string {
	if runtime.GOOS == "windows" {
		return "adb.exe"
	}
	return "adb"
}

func TestExtractKeepsPlatformToolsOnly(t *testing.T) {
	archive := writeZip(t, map[string]string{
		"platform-tools/" + adbName():    "bin",
		"platform-tools/lib64/libc++.so": "lib",
		"other/readme.txt":               "skip",
	})
	dst := t.TempDir()
	if err := extract(archive, dst); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(localBinary(dst))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o111 == 0 {
		t.Errorf("adb is not executable: %v", st.Mode())
	}
	if _, err := os.Stat(filepath.Join(dst, "platform-tools", "lib64", "libc++.so")); err != nil {
		t.Error("library not extracted")
	}
	if _, err := os.Stat(filepath.Join(dst, "other")); !os.IsNotExist(err) {
		t.Error("entry outside platform-tools/ was extracted")
	}
}

func TestExtractRejectsTraversal(t *testing.T) {
	archive := writeZip(t, map[string]string{
		"platform-tools/../../evil": "x",
	})
	dst := t.TempDir()
	_ = extract(archive, dst)
	if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "evil")); !os.IsNotExist(err) {
		t.Fatal("zip entry escaped the destination")
	}
}

func TestEnsureFallsBackToDownloadedCopy(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv("STATION_TOOL_ADB", "")
	dir := t.TempDir()
	if _, err := Ensure(dir, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	p := localBinary(dir)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	c, err := Ensure(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.bin != p || !c.own {
		t.Fatalf("unexpected client: bin=%q own=%v", c.bin, c.own)
	}
}
