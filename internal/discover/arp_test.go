package discover

import "testing"

func TestParseNeighMAC(t *testing.T) {
	cases := []struct {
		name string
		out  string
		ip   string
		want string
	}{
		{
			name: "windows english",
			out: "Interface: 192.168.178.20 --- 0x8\n" +
				"  Internet Address      Physical Address      Type\n" +
				"  192.168.178.63        a8-80-2e-11-22-33     dynamic\n",
			ip:   "192.168.178.63",
			want: "a8:80:2e:11:22:33",
		},
		{
			name: "windows russian",
			out: "Интерфейс: 192.168.178.20 --- 0x8\n" +
				"  Интернет-адрес      Физический адрес     Тип\n" +
				"  192.168.178.63      a8-80-2e-11-22-33    динамический\n",
			ip:   "192.168.178.63",
			want: "a8:80:2e:11:22:33",
		},
		{
			name: "windows interface line carries no mac",
			out:  "Интерфейс: 192.168.178.63 --- 0x8\n",
			ip:   "192.168.178.63",
			want: "",
		},
		{
			name: "ip neigh",
			out:  "192.168.178.63 dev wlan0 lladdr a8:80:2e:11:22:33 REACHABLE\n",
			ip:   "192.168.178.63",
			want: "a8:80:2e:11:22:33",
		},
		{
			name: "ip neigh incomplete has no lladdr",
			out:  "192.168.178.63 dev wlan0 INCOMPLETE\n",
			ip:   "192.168.178.63",
			want: "",
		},
		{
			name: "arp bsd",
			out:  "? (192.168.178.63) at a8:80:2e:11:22:33 on en0 ifscope [ethernet]\n",
			ip:   "192.168.178.63",
			want: "a8:80:2e:11:22:33",
		},
		{
			name: "arp bsd incomplete",
			out:  "? (192.168.178.63) at (incomplete) on en0 ifscope [ethernet]\n",
			ip:   "192.168.178.63",
			want: "",
		},
		{
			name: "other host lines ignored",
			out: "192.168.178.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n" +
				"192.168.178.63 dev wlan0 lladdr a8:80:2e:11:22:33 STALE\n",
			ip:   "192.168.178.63",
			want: "a8:80:2e:11:22:33",
		},
		{
			name: "substring ip does not match other hosts",
			out:  "192.168.178.6 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n",
			ip:   "192.168.178.63",
			want: "",
		},
		{
			name: "prefix query does not match longer host",
			out:  "192.168.178.63 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n",
			ip:   "192.168.178.6",
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseNeighMAC(c.out, c.ip); got != c.want {
				t.Fatalf("parseNeighMAC = %q, want %q", got, c.want)
			}
		})
	}
}
