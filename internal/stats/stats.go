// Package stats reads a station's live resource usage for the overview
// widgets. Every value comes from its own read-only shell command so the
// journal shows exactly what was read.
//
// The set of sources follows github.com/dimap/yandex-station-web (MIT).
package stats

import (
	"errors"
	"strconv"
	"strings"
)

// Commands are issued in this order, one shell call each.
var (
	CmdTemp    = "cat /sys/class/thermal/thermal_zone0/temp"
	CmdMem     = "cat /proc/meminfo"
	CmdUptime  = "cat /proc/uptime"
	CmdLoad    = "cat /proc/loadavg"
	CmdSignal  = "wpa_cli -i wlan0 signal_poll"
	CmdWiFi    = "wpa_cli -i wlan0 status"
	CmdData    = "df -k /data"
	AllQueries = []string{CmdTemp, CmdMem, CmdUptime, CmdLoad, CmdSignal, CmdWiFi, CmdData}
)

type Stats struct {
	TempC       *float64   `json:"tempC"`
	MemTotalKB  int64      `json:"memTotalKB"`
	MemAvailKB  int64      `json:"memAvailKB"`
	UptimeSec   float64    `json:"uptimeSec"`
	Load        [3]float64 `json:"load"`
	LoadKnown   bool       `json:"loadKnown"`
	RSSI        *int       `json:"rssi"`
	LinkMbps    int        `json:"linkMbps"`
	FreqMHz     int        `json:"freqMHz"`
	SSID        string     `json:"ssid"`
	DataTotalKB int64      `json:"dataTotalKB"`
	DataFreeKB  int64      `json:"dataFreeKB"`
}

// Collect runs each query through run. A failing query only leaves its
// fields empty; Collect fails only when every query fails.
func Collect(run func(cmd string) (string, error)) (Stats, error) {
	var s Stats
	ok := 0
	read := func(cmd string, parse func(string) bool) {
		out, err := run(cmd)
		if err != nil && strings.TrimSpace(out) == "" {
			return
		}
		if parse(out) {
			ok++
		}
	}
	read(CmdTemp, func(out string) bool {
		v, err := strconv.ParseFloat(strings.TrimSpace(out), 64)
		if err != nil {
			return false
		}
		// thermal_zone temp is in millidegrees Celsius.
		c := v / 1000
		s.TempC = &c
		return true
	})
	read(CmdMem, func(out string) bool {
		s.MemTotalKB = meminfoKB(out, "MemTotal")
		s.MemAvailKB = meminfoKB(out, "MemAvailable")
		return s.MemTotalKB > 0
	})
	read(CmdUptime, func(out string) bool {
		f := strings.Fields(out)
		if len(f) == 0 {
			return false
		}
		v, err := strconv.ParseFloat(f[0], 64)
		if err != nil {
			return false
		}
		s.UptimeSec = v
		return true
	})
	read(CmdLoad, func(out string) bool {
		f := strings.Fields(out)
		if len(f) < 3 {
			return false
		}
		for i := 0; i < 3; i++ {
			v, err := strconv.ParseFloat(f[i], 64)
			if err != nil {
				return false
			}
			s.Load[i] = v
		}
		s.LoadKnown = true
		return true
	})
	read(CmdSignal, func(out string) bool {
		kv := keyValues(out)
		if v, err := strconv.Atoi(kv["RSSI"]); err == nil {
			s.RSSI = &v
		}
		s.LinkMbps, _ = strconv.Atoi(kv["LINKSPEED"])
		s.FreqMHz, _ = strconv.Atoi(kv["FREQUENCY"])
		return s.RSSI != nil
	})
	read(CmdWiFi, func(out string) bool {
		kv := keyValues(out)
		s.SSID = kv["ssid"]
		if s.FreqMHz == 0 {
			s.FreqMHz, _ = strconv.Atoi(kv["freq"])
		}
		return s.SSID != "" || kv["wpa_state"] != ""
	})
	read(CmdData, func(out string) bool {
		s.DataTotalKB, s.DataFreeKB = dfDataKB(out)
		return s.DataTotalKB > 0
	})
	if ok == 0 {
		return s, errors.New("no resource counters could be read")
	}
	return s, nil
}

// dfDataKB parses `df -k /data` output into total and available KiB. df
// itself resolves the path, so the answer row is the last numeric row —
// never matched by mount name: on the Amlogic AXG stations (Lite, Mini,
// Mini 2, Station 2, Street) /data is a symlink into the /bkupgrade ubifs
// volume and the row prints as /bkupgrade, while Midi and the Android
// stations have a real /data partition.
func dfDataKB(out string) (total, free int64) {
	var t, f int64
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		// Filesystem 1K-blocks Used Available Use% Mounted-on
		if len(fields) < 6 {
			continue
		}
		tv, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue // header or error text
		}
		fv, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil {
			continue
		}
		t, f = tv, fv
	}
	return t, f
}

func meminfoKB(out, key string) int64 {
	for _, line := range strings.Split(out, "\n") {
		name, rest, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(name) != key {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			return 0
		}
		v, _ := strconv.ParseInt(f[0], 10, 64)
		return v
	}
	return 0
}

func keyValues(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, found := strings.Cut(strings.TrimSpace(line), "=")
		if found {
			m[k] = v
		}
	}
	return m
}
