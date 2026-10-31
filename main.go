// Yandex Station ToolKit manages rooted Yandex Stations on the LAN.
package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"os"

	"github.com/saintonotole/yandex-station-toolkit/internal/discover"
	"github.com/saintonotole/yandex-station-toolkit/internal/firmware"
	"github.com/saintonotole/yandex-station-toolkit/internal/server"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend
var frontendFS embed.FS

// version is set at build time via -ldflags -X main.version=…
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	selfTest := flag.Bool("selftest", false, "run non-GUI self checks and exit")
	serverHelper := flag.Bool("Server-helper", false, "internal: run the elevated bootstrap endpoints")
	flag.Parse()

	if *showVersion {
		fmt.Println("Yandex Station ToolKit", version)
		return
	}
	if *selfTest {
		selftest()
		return
	}
	if *serverHelper {
		os.Exit(runServerHelper())
	}

	app := newApp()

	err := wails.Run(&options.App{
		Title:     "Yandex Station ToolKit",
		Width:     1080,
		Height:    780,
		MinWidth:  960,
		MinHeight: 680,
		AssetServer: &assetserver.Options{
			Assets: mustSub(),
		},
		OnStartup:  app.Startup,
		OnShutdown: app.Shutdown,
		Windows: &windows.Options{
			Theme: windows.Dark,
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "startup failed:", err)
		os.Exit(1)
	}
}

func mustSub() fs.FS {
	sub, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		panic(err)
	}
	return sub
}

// runServerHelper is the elevated half of the bootstrap: it reads JSON
// commands from stdin (start/setMode/stop/shutdown) and writes events to
// stdout. The GUI spawns it through pkexec with pipes, so root code runs
// only here, serving DNS and the HTTPS endpoint. Firmware files are
// downloaded by the GUI as the user; this side only reads them.
func runServerHelper() int {
	cert, err := payload(payloadEquasarChain)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	key, err := payload(payloadEquasarKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	tmpl, err := payload(payloadSyncTemplate)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	cfg := server.HelperConfig{
		CertPEM:      cert,
		KeyPEM:       key,
		SyncTemplate: tmpl,
		MakeProvider: func(dir string, log func(string)) server.FirmwareProvider {
			return firmware.NewProvider(firmware.New(dir, "", log), localLANIP, log)
		},
	}
	if err := server.RunHelper(cfg, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func selftest() {
	fmt.Println("Yandex Station ToolKit", version)
	fmt.Println("payloads:")
	for name, ok := range payloadStatus() {
		fmt.Printf("  %-18s %v\n", name, ok)
	}
	nets, err := discover.LocalNetworks()
	if err != nil {
		fmt.Println("networks: error:", err)
	} else {
		fmt.Println("networks:")
		for _, n := range nets {
			fmt.Println("  ", n)
		}
	}
}
