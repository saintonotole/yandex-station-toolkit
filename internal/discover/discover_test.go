package discover

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestHosts(t *testing.T) {
	_, n24, _ := net.ParseCIDR("192.168.1.0/24")
	hosts := Hosts(n24, MaxHosts)
	if len(hosts) != 254 {
		t.Fatalf("/24: got %d hosts, want 254", len(hosts))
	}
	if hosts[0] != "192.168.1.1" || hosts[253] != "192.168.1.254" {
		t.Fatalf("bad bounds: %v .. %v", hosts[0], hosts[253])
	}

	_, n25, _ := net.ParseCIDR("192.168.1.128/25")
	hosts = Hosts(n25, MaxHosts)
	if len(hosts) != 126 || hosts[0] != "192.168.1.129" {
		t.Fatalf("/25: got %d hosts starting at %s", len(hosts), hosts[0])
	}

	_, n31, _ := net.ParseCIDR("10.0.0.4/31")
	if got := Hosts(n31, MaxHosts); len(got) != 1 || got[0] != "10.0.0.4" {
		t.Fatalf("/31: %v", got)
	}

	_, n22, _ := net.ParseCIDR("172.16.0.0/22")
	if got := len(Hosts(n22, 100)); got != 100 {
		t.Fatalf("limit: got %d", got)
	}
}

func TestParseRanges(t *testing.T) {
	nets, err := ParseRanges("192.168.1.5, 10.0.0.0/24;172.16.0.5/12")
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 3 {
		t.Fatalf("got %d nets", len(nets))
	}
	if nets[0].String() != "192.168.1.5/32" {
		t.Fatalf("ip: %s", nets[0])
	}
	// /12 is capped at /16.
	if nets[2].String() != "172.16.0.0/16" {
		t.Fatalf("wide: %s", nets[2])
	}
	if _, err := ParseRanges("not-an-ip"); err == nil {
		t.Fatal("expected error")
	}
}

func TestRetailSKU(t *testing.T) {
	if got := RetailSKU("Станция Лайт"); got != "YNDX-00025" {
		t.Fatalf("lite: %q", got)
	}
	if got := RetailSKU("Станция Лайт 2"); !strings.Contains(got, "YNDX-00026") || !strings.Contains(got, "YNDX-00028") {
		t.Fatalf("lite2: %q", got)
	}
	if got := RetailSKU("Станция 2"); got != "YNDX-00051" {
		t.Fatalf("station2: %q", got)
	}
	if RetailSKU("неизвестно") != "" {
		t.Fatal("unknown must be empty")
	}
}

func TestPlatformModelResolvesLite(t *testing.T) {
	if got := PlatformModel("yandexmicro"); got != "Станция Лайт" {
		t.Fatalf("yandexmicro: %q", got)
	}
	if PlatformModel("yandexplum") != "Станция Лайт 2" {
		t.Fatal("plum")
	}
	if PlatformModel("unknown") != "" {
		t.Fatal("unknown must be empty")
	}
}

func TestModelIconAndColors(t *testing.T) {
	if ModelIcon("Станция Лайт") != "micro_mint.png" {
		t.Fatal("light generic icon")
	}
	if len(ModelColors("Станция Лайт")) == 0 {
		t.Fatal("light colors missing")
	}
	if ModelColorIcons("Станция Лайт")["mint"] != "micro_mint.png" {
		t.Fatal("light mint icon")
	}
}

func TestIsVirtualInterface(t *testing.T) {
	virtual := []string{"docker0", "br-abcdef", "veth1234", "vEthernet (DockerNAT)",
		"vboxnet0", "vmnet1", "virbr0", "tap0", "tun0", "utun0", "utun10", "hns0", "ws-l0", "wsl0",
		"ppp0", "ipsec0", "wg0",
		"Hyper-V Virtual", "vEthernet (Default Switch)"}
	for _, n := range virtual {
		if !IsVirtualInterface(n) {
			t.Errorf("IsVirtualInterface(%q) = false, want true", n)
		}
	}
	physical := []string{"Ethernet", "Wi-Fi", "eth0", "wlan0", "en0"}
	for _, n := range physical {
		if IsVirtualInterface(n) {
			t.Errorf("IsVirtualInterface(%q) = true, want false", n)
		}
	}
}

func TestCollect(t *testing.T) {
	files := map[string]string{
		"cat /proc/device-tree/model":            "Yandex Station Mini 2\x00",
		"cat /proc/device-tree/compatible":       "yandex,station-mini2\x00amlogic, axg\x00",
		"id -u":                                  "0\n",
		"cat /system/vendor/quasar/version_full": "",
		"cat /system/vendor/quasar/VERSION":      "1.2.3\n",
	}
	d := &Device{Hostname: "from-mdns"}
	err := Collect(func(cmd string) (string, error) {
		if s, ok := files[cmd]; ok {
			if s == "" {
				return "", fmt.Errorf("missing")
			}
			return s, nil
		}
		return "", fmt.Errorf("missing")
	}, d)
	if err != nil {
		t.Fatal(err)
	}
	if d.ModelRaw != "Yandex Station Mini 2" || d.Compat != "yandex,station-mini2" || !d.Root || d.Firmware != "1.2.3" {
		t.Fatalf("%+v", d)
	}
	if d.Model != "Станция Мини 2" {
		t.Fatalf("model %q", d.Model)
	}
	if d.Hostname != "from-mdns" {
		t.Fatalf("hostname overwritten: %q", d.Hostname)
	}
}

func TestModelName(t *testing.T) {
	cases := []struct{ compat, model, want string }{
		{"yandex,station-mini2", "Yandex Station Mini 2", "Станция Мини 2"},
		{"yandex,station-mini3\x00amlogic,axg\x00", "Yandex Station Mini 3", "Станция Мини 3"},
		{"yandex,station-mini", "Yandex Station Mini", "Станция Мини"},
		{"yandex,station-micro", "Yandex Station Micro v1.2", "Станция Лайт"},
		{"yandex,plum", "", "Станция Лайт 2"},
		{"amlogic,axg", "Yandex Station Mini", "Станция Мини"},
		{"yandex,pickle-evt", "Yandex Station Mini 3 Pro", "Станция Мини 3 Про"},
		{"tulip-d1", "Yandex Station Gen1", "Станция (1-го поколения)"},
		// station-midi is retail Станция 2, not Миди.
		{"yandex,station-midi", "Yandex Station Midi", "Станция 2"},
		{"yandex,cucumber-dvt2", "Yandex Cucumber DVT2", "Станция Миди"},
		{"", "Yandex Station Mango DVT", "Станция Стрит"},
		{"yandex,saturn", "Yandex Saturn", "Умный хаб"},
		{"something,else", "Weird Device", ""},
		// station-mini must not shadow the mini2/mini3 rules.
		{"", "Yandex Station Mini 3", "Станция Мини 3"},
	}
	for _, c := range cases {
		if got := ModelName(c.compat, c.model); got != c.want {
			t.Errorf("ModelName(%q,%q)=%q want %q", c.compat, c.model, got, c.want)
		}
	}
}

func TestSortedDevices(t *testing.T) {
	m := map[string]*Device{
		"192.168.1.9":  {IP: "192.168.1.9"},
		"192.168.1.10": {IP: "192.168.1.10"},
		"192.168.1.2":  {IP: "192.168.1.2"},
	}
	got := SortedDevices(m)
	if got[0].IP != "192.168.1.2" || got[1].IP != "192.168.1.9" || got[2].IP != "192.168.1.10" {
		t.Fatalf("order: %v", got)
	}
}
