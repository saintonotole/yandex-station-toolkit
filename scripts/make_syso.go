// make_syso generates a Windows .syso resource file with the app icon
// pinned at resource ID 3 — the ID wails v2 on Windows loads for the
// window title-bar icon (AppIconID = 3 in
// internal/frontend/desktop/windows/winc/app.go).
//
// `rsrc -ico` alone puts the icon group at ID 1 (or 2 with a manifest),
// so the window falls back to a generic icon. This program uses the
// rsrc library directly to place the group at ID 3.
//
// Usage: go run scripts/make_syso.go -ico assets/windows/icon.ico -manifest assets/windows/app.manifest -o resource_windows_amd64.syso
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/akavel/rsrc/binutil"
	"github.com/akavel/rsrc/coff"
	"github.com/akavel/rsrc/ico"
)

// RT_VERSION — the rsrc package defines only the icon and manifest types.
const rsrcTypeVersion uint32 = 16

// Minimal reimplementation of rsrc.Embed with a fixed group-icon ID.
// We add: manifest at ID 1, icon group at ID 3, individual icons at 4+.

type grpIconDirEntry struct {
	ico.IconDirEntryCommon
	ID uint16
}

type grpIconDir struct {
	ico.ICONDIR
	Entries []grpIconDirEntry
}

// Size makes grpIconDir satisfy coff.Sizer. Matches the layout
// rsrc uses: ICONDIR header + N entries.
func (g grpIconDir) Size() int64 {
	return int64(binary.Size(g.ICONDIR) + len(g.Entries)*binary.Size(g.Entries[0]))
}

func main() {
	var icoFile, manifestFile, outFile, arch, version string
	flag.StringVar(&icoFile, "ico", "", "path to .ico file")
	flag.StringVar(&manifestFile, "manifest", "", "path to .manifest file (optional)")
	flag.StringVar(&outFile, "o", "resource_windows_amd64.syso", "output .syso path")
	flag.StringVar(&arch, "arch", "amd64", "architecture: 386|amd64|arm64")
	flag.StringVar(&version, "version", "dev", "version identifier for the VERSIONINFO resource (e.g. v1.2.3; non-numeric stays 0.0.0.0)")
	flag.Parse()

	if icoFile == "" && manifestFile == "" {
		fmt.Fprintln(os.Stderr, "need -ico and/or -manifest")
		os.Exit(2)
	}

	out := coff.NewRSRC()
	if err := out.Arch(arch); err != nil {
		fmt.Fprintln(os.Stderr, "arch:", err)
		os.Exit(1)
	}

	// Manifest at resource ID 1 (RT_MANIFEST = 24).
	if manifestFile != "" {
		f, err := binutil.SizedOpen(manifestFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "manifest:", err)
			os.Exit(1)
		}
		defer f.Close()
		out.AddResource(coff.RT_MANIFEST, 1, f)
	}

	// VERSIONINFO at resource ID 1 (RT_VERSION = 16): file and product
	// version derived from the release tag, shown by Explorer's Details tab.
	out.AddResource(rsrcTypeVersion, 1, bytes.NewReader(versionResource(version)))

	// Icon group at resource ID 3 (what wails AppIconID expects).
	if icoFile != "" {
		f, err := addIconAt(out, icoFile, 3)
		if err != nil {
			fmt.Fprintln(os.Stderr, "icon:", err)
			os.Exit(1)
		}
		defer f.Close()
	}

	out.Freeze()
	if err := writeCOFF(out, outFile); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Println("wrote", outFile)
}

// writeCOFF serializes the COFF resource object to a .syso file.
// Reimplemented here because rsrc's internal.Write is not importable
// from outside the module — uses the exported binutil + coff packages.
func writeCOFF(c *coff.Coff, fnameout string) error {
	out, err := os.Create(fnameout)
	if err != nil {
		return err
	}
	defer out.Close()
	w := binutil.Writer{W: out}
	binutil.Walk(c, func(v reflect.Value, path string) error {
		if binutil.Plain(v.Kind()) {
			w.WriteLE(v.Interface())
			return nil
		}
		vv, ok := v.Interface().(binutil.SizedReader)
		if ok {
			w.WriteFromSized(vv)
			return binutil.WALK_SKIP
		}
		return nil
	})
	if w.Err != nil {
		return fmt.Errorf("write: %w", w.Err)
	}
	return nil
}

// addIconAt adds the icon group at groupID and individual icon entries
// at groupID+1, groupID+2, … Returns the open file handle so the
// caller can keep it open until writeCOFF has read all the data.
func addIconAt(out *coff.Coff, fname string, groupID uint16) (*os.File, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}

	icons, err := ico.DecodeHeaders(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	if len(icons) == 0 {
		f.Close()
		return nil, fmt.Errorf("no icons in %s", fname)
	}

	group := grpIconDir{ICONDIR: ico.ICONDIR{
		Reserved: 0,
		Type:     1,
		Count:    uint16(len(icons)),
	}}
	nextID := groupID + 1 // individual icons start after the group
	for _, icon := range icons {
		r := io.NewSectionReader(f, int64(icon.ImageOffset), int64(icon.BytesInRes))
		out.AddResource(coff.RT_ICON, nextID, r)
		group.Entries = append(group.Entries, grpIconDirEntry{icon.IconDirEntryCommon, nextID})
		nextID++
	}
	out.AddResource(coff.RT_GROUP_ICON, groupID, group)
	return f, nil
}

// --- VS_VERSIONINFO ----------------------------------------------------------
// Layout per the PE specification, byte-for-byte against real resources:
// UTF-16LE text, every block 4-byte aligned, block sizes include the
// alignment padding, string value lengths are counted in words (2-byte
// units) including the terminating null.

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, w := range u {
		binary.LittleEndian.PutUint16(b[2*i:], w)
	}
	return b
}

// padKey pads a UTF-16 key with its null terminator so that, after the
// 6-byte block header, the next block starts on a 4-byte boundary.
func padKey(b []byte) []byte {
	b = append(b, 0, 0)
	for (len(b)+6)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// padValue pads a UTF-16 value with its null terminator to a 4-byte boundary.
func padValue(b []byte) []byte {
	b = append(b, 0, 0)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func blockHeader(total, valueLength int, text bool) []byte {
	h := make([]byte, 6)
	binary.LittleEndian.PutUint16(h[0:], uint16(total))
	binary.LittleEndian.PutUint16(h[2:], uint16(valueLength))
	t := uint16(0)
	if text {
		t = 1
	}
	binary.LittleEndian.PutUint16(h[4:], t)
	return h
}

// stringStruct renders one Key/Value pair of the string table.
func stringStruct(key, value string) []byte {
	k := padKey(utf16le(key))
	v := padValue(utf16le(value))
	total := 6 + len(k) + len(v)
	out := blockHeader(total, len(utf16le(value))/2+1, true)
	out = append(out, k...)
	return append(out, v...)
}

// container renders a named block holding children (StringFileInfo,
// StringTable): the children are already aligned, so the size is their sum.
func container(key string, children []byte) []byte {
	k := padKey(utf16le(key))
	total := 6 + len(k) + len(children)
	out := blockHeader(total, 0, true)
	out = append(out, k...)
	return append(out, children...)
}

// fixedFileInfo renders the 52-byte numeric version block: file and product
// version as 1.2.3.0, VFT_APP.
func fixedFileInfo(ms, ls uint32) []byte {
	b := make([]byte, 52)
	binary.LittleEndian.PutUint32(b[0:], 0xFEEF04BD)
	binary.LittleEndian.PutUint32(b[4:], 0x00010000)
	binary.LittleEndian.PutUint32(b[8:], ms)
	binary.LittleEndian.PutUint32(b[12:], ls)
	binary.LittleEndian.PutUint32(b[16:], ms)
	binary.LittleEndian.PutUint32(b[20:], ls)
	binary.LittleEndian.PutUint32(b[24:], 0x0000003F) // flag mask
	// flags, file subtype and file date stay zero
	binary.LittleEndian.PutUint32(b[32:], 0x00040004) // VOS_NT_WINDOWS32
	binary.LittleEndian.PutUint32(b[36:], 1)          // VFT_APP
	return b
}

// parseVersion turns a release tag into the numeric 1.2.3.0 parts and the
// human-readable string. Non-numeric identifiers ("dev") become 0.0.0.0.
func parseVersion(s string) (ms, ls uint32, str string) {
	s = strings.TrimPrefix(s, "v")
	str = s
	num := func(p string) uint32 {
		end := 0
		for end < len(p) && p[end] >= '0' && p[end] <= '9' {
			end++
		}
		n, _ := strconv.Atoi(p[:end])
		return uint32(n)
	}
	parts := strings.Split(s, ".")
	major, minor, patch := num(parts[0]), uint32(0), uint32(0)
	if len(parts) > 1 {
		minor = num(parts[1])
	}
	if len(parts) > 2 {
		patch = num(parts[2])
	}
	return major<<16 | minor, patch << 16, str
}

// versionResource renders the whole VS_VERSIONINFO resource (a StringFileInfo
// table in US English/Unicode; the optional VarFileInfo block is omitted).
func versionResource(version string) []byte {
	ms, ls, str := parseVersion(version)
	pairs := [][2]string{
		{"CompanyName", "saintonotole"},
		{"FileDescription", "Yandex Station ToolKit"},
		{"FileVersion", str},
		{"InternalName", "yandex-station-toolkit"},
		{"LegalCopyright", "© 2026 saintonotole"},
		{"OriginalFilename", "Yandex Station ToolKit.exe"},
		{"ProductName", "Yandex Station ToolKit"},
		{"ProductVersion", str},
	}
	var table []byte
	for _, p := range pairs {
		table = append(table, stringStruct(p[0], p[1])...)
	}
	sfi := container("StringFileInfo", container("040904b0", table))

	rootKey := padKey(utf16le("VS_VERSION_INFO"))
	body := append(fixedFileInfo(ms, ls), sfi...)
	total := 6 + len(rootKey) + len(body)
	out := blockHeader(total, 52, false)
	out = append(out, rootKey...)
	out = append(out, body...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}
