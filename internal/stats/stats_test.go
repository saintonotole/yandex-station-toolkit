package stats

import (
	"errors"
	"testing"
)

func TestCollect(t *testing.T) {
	answers := map[string]string{
		CmdTemp:   "52300\n",
		CmdMem:    "MemTotal:         243712 kB\nMemFree:           20000 kB\nMemAvailable:     109568 kB\n",
		CmdUptime: "10748.21 39000.00\n",
		CmdLoad:   "8.45 6.25 5.25 3/180 2345\n",
		CmdSignal: "RSSI=-42\nLINKSPEED=390\nNOISE=9999\nFREQUENCY=5180\n",
		CmdWiFi:   "bssid=aa:bb:cc:dd:ee:ff\nfreq=5180\nssid=home\nwpa_state=COMPLETED\n",
		// Real answer from a Станция Лайт: /data is a symlink into /bkupgrade.
		CmdData: "Filesystem           1K-blocks      Used Available Use% Mounted on\n/dev/ubi1_0              89568      5512     79448   6% /bkupgrade\n",
	}
	s, err := Collect(func(cmd string) (string, error) {
		if out, ok := answers[cmd]; ok {
			return out, nil
		}
		return "", errors.New("unexpected " + cmd)
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.TempC == nil || *s.TempC != 52.3 {
		t.Fatalf("temp: %v", s.TempC)
	}
	if s.MemTotalKB != 243712 || s.MemAvailKB != 109568 {
		t.Fatalf("mem: %d/%d", s.MemAvailKB, s.MemTotalKB)
	}
	if s.UptimeSec != 10748.21 {
		t.Fatalf("uptime: %v", s.UptimeSec)
	}
	if !s.LoadKnown || s.Load != [3]float64{8.45, 6.25, 5.25} {
		t.Fatalf("load: %v", s.Load)
	}
	if s.RSSI == nil || *s.RSSI != -42 || s.LinkMbps != 390 || s.FreqMHz != 5180 || s.SSID != "home" {
		t.Fatalf("wifi: %+v", s)
	}
	if s.DataTotalKB != 89568 || s.DataFreeKB != 79448 {
		t.Fatalf("data: total=%d free=%d", s.DataTotalKB, s.DataFreeKB)
	}
}

func TestDfDataParse(t *testing.T) {
	// A real /data partition (Midi, Android stations): the row carries the
	// /data name and must parse the same way.
	total, free := dfDataKB("Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/block/mmcblk0p12 2857968 1490048 1367920 52% /data\n")
	if total != 2857968 || free != 1367920 {
		t.Fatalf("real /data row: %d/%d", total, free)
	}
	// Symlink case: df prints the underlying /bkupgrade mount (Lite, Mini).
	total, free = dfDataKB("Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/ubi1_0 89568 5512 79448 6% /bkupgrade\n")
	if total != 89568 || free != 79448 {
		t.Fatalf("symlink row: %d/%d", total, free)
	}
	// A failing query (no /data, permission, toybox error text) leaves zeros.
	total, free = dfDataKB("df: /data: No such file or directory\n")
	if total != 0 || free != 0 {
		t.Fatalf("error text: %d/%d", total, free)
	}
}

func TestCollectPartialAndEmpty(t *testing.T) {
	s, err := Collect(func(cmd string) (string, error) {
		if cmd == CmdUptime {
			return "61.0 10.0\n", nil
		}
		return "", errors.New("not found")
	})
	if err != nil || s.UptimeSec != 61 || s.TempC != nil || s.RSSI != nil {
		t.Fatalf("partial: %+v %v", s, err)
	}
	if _, err := Collect(func(string) (string, error) { return "", errors.New("down") }); err == nil {
		t.Fatal("expected an error when nothing could be read")
	}
}
