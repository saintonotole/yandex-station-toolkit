package discover

import (
	"sort"
	"strings"
)

type Model struct {
	Retail   string
	SKU      string   // clock and no-clock variants list both codes, separated by " / "
	Compat   string   // device-tree compatible; empty on Android stations
	Platform string   // mDNS TXT platform, the authoritative model marker
	Hostname string   // only for models whose platform does not identify them
	Colors   []string // from the Alice app's iot_station_<icon>_<color> drawables
	Icon     string   // official identify-page icon
	Icons    map[string]string
}

var models = []Model{
	{
		Retail: "Станция Лайт", SKU: "YNDX-00025",
		Compat: "yandex,station-micro", Platform: "yandexmicro",
		Colors: []string{"mint", "pink", "purple", "red", "yellow", "beige"},
		Icon:   "micro_mint.png",
		Icons: map[string]string{
			"mint":   "micro_mint.png",
			"pink":   "micro_pink.png",
			"purple": "micro_purple.png",
			"red":    "micro_red.png",
			"yellow": "micro_yellow.png",
			"beige":  "micro_beige.png",
		},
	},
	{
		Retail: "Станция Лайт 2", SKU: "YNDX-00026 / YNDX-00028",
		Compat: "yandex,plum", Platform: "plum",
		// The APK palette: the clock SKU (YNDX-00026) and the plain one
		// (YNDX-00028) share it; clock keys pick the clock renders.
		Colors: []string{"blue", "coral", "gray", "green", "lilac", "pink",
			"clock-blue", "clock-coral", "clock-gray", "clock-green",
			"clock-lilac", "clock-pink"},
		Icon: "plum_blue.png",
		Icons: map[string]string{
			"blue":        "plum_blue.png",
			"coral":       "plum_coral.png",
			"gray":        "plum_gray.png",
			"green":       "plum_green.png",
			"lilac":       "plum_lilac.png",
			"pink":        "plum_pink.png",
			"clock-blue":  "plum_clock_blue.png",
			"clock-coral": "plum_clock_coral.png",
			"clock-gray":  "plum_clock_gray.png",
			"clock-green": "plum_clock_green.png",
			"clock-lilac": "plum_clock_lilac.png",
			"clock-pink":  "plum_clock_pink.png",
		},
	},
	{
		Retail: "Станция Мини", SKU: "YNDX-0004",
		// 1st gen shares the generic AXG device-tree; no yandex compat.
		// Platform verified from the official Mini firmware's quasar.cfg
		// (deviceType "yandexmini").
		Compat: "amlogic,axg", Platform: "yandexmini",
		Colors: []string{"black", "white"},
		Icon:   "mini_black.png",
		Icons:  map[string]string{"black": "mini_black.png"},
	},
	{
		Retail: "Станция Мини 2", SKU: "YNDX-00020 / YNDX-00021",
		Compat: "yandex,station-mini2", Platform: "yandexmini_2",
		// YNDX-00020 is the clock SKU, YNDX-00021 the plain one; the mDNS
		// data does not tell them apart, so the clock variants are
		// selectable like colors.
		Colors: []string{"black", "blue", "red", "white",
			"clock-black", "clock-blue", "clock-red", "clock-white"},
		Icon: "mini2_black.png",
		Icons: map[string]string{
			"black":       "mini2_black.png",
			"blue":        "mini2_blue.png",
			"red":         "mini2_red.png",
			"white":       "mini2_white.png",
			"clock-black": "mini2_clock_black.png",
			"clock-blue":  "mini2_clock_blue.png",
			"clock-red":   "mini2_clock_red.png",
			"clock-white": "mini2_clock_white.png",
		},
	},
	{
		Retail: "Станция Мини 3", SKU: "YNDX-00027",
		Compat: "yandex,station-mini3", Platform: "bergamot",
		Colors: []string{"black", "gray", "violet"},
		Icon:   "bergamot_black.png",
		Icons: map[string]string{
			"black":  "bergamot_black.png",
			"gray":   "bergamot_gray.png",
			"violet": "bergamot_violet.png",
		},
	},
	{
		Retail: "Станция Мини 3 Про", SKU: "YNDX-00059",
		Compat: "yandex,pickle-evt", Platform: "pickle",
		Colors: []string{"black", "blue", "gray", "green", "violet"},
		Icon:   "pickle_black.png",
		Icons: map[string]string{
			"black":  "pickle_black.png",
			"blue":   "pickle_blue.png",
			"gray":   "pickle_gray.png",
			"green":  "pickle_green.png",
			"violet": "pickle_violet.png",
		},
	},
	{
		// yandex,station-midi (DT) is retail "Станция 2", not "Миди" (wiki).
		Retail: "Станция 2", SKU: "YNDX-00051",
		Compat: "yandex,station-midi", Platform: "yandexmidi",
		Colors: []string{"beige", "black", "blue", "copper", "ruby"},
		Icon:   "midi_black.png",
		Icons: map[string]string{
			"beige":  "midi_beige.png",
			"black":  "midi_black.png",
			"blue":   "midi_blue.png",
			"copper": "midi_copper.png",
			"ruby":   "midi_ruby.png",
		},
	},
	{
		// retail "Станция Миди" = codename Cucumber (wiki).
		Retail: "Станция Миди", SKU: "YNDX-00054",
		Compat: "yandex,cucumber", Platform: "cucumber",
		Hostname: "yandex-station-midi",
		Colors:   []string{"black", "gray", "orange", "raspberry", "turquoise"},
		Icon:     "cucumber_black.png",
		Icons: map[string]string{
			"black":     "cucumber_black.png",
			"gray":      "cucumber_gray.png",
			"orange":    "cucumber_orange.png",
			"raspberry": "cucumber_raspberry.png",
			"turquoise": "cucumber_turquoise.png",
		},
	},
	{
		Retail: "Станция Стрит", SKU: "YNDX-00030",
		Compat: "yandex,station-mango", Platform: "mango",
		Hostname: "yandexmango",
		Colors:   []string{"black", "gray", "green", "orange", "violet"},
		Icon:     "mango_black.png",
		Icons: map[string]string{
			"black":  "mango_black.png",
			"gray":   "mango_gray.png",
			"green":  "mango_green.png",
			"orange": "mango_orange.png",
			"violet": "mango_violet.png",
		},
	},
	{
		Retail: "Станция Дуо Макс", SKU: "YNDX-00055",
		Compat: "yandex,station-chiron", Platform: "chiron",
		Colors: []string{"beige", "black", "green", "red"},
		Icon:   "chiron_black.png",
		Icons: map[string]string{
			"beige": "chiron_beige.png",
			"black": "chiron_black.png",
			"green": "chiron_green.png",
			"red":   "chiron_red.png",
		},
	},
	{
		Retail: "Станция 3", SKU: "YNDX-00060",
		Compat: "yandex,station-orion", Platform: "orion",
		Colors: []string{"black", "gray", "violet"},
		Icon:   "orion_black.png",
		Icons: map[string]string{
			"black":  "orion_black.png",
			"gray":   "orion_gray.png",
			"violet": "orion_violet.png",
		},
	},
	{
		Retail: "Умный хаб", SKU: "",
		Compat: "yandex,saturn", Platform: "saturn",
		Hostname: "yandexsaturn",
	},
	{
		// yandexstation_2 (Android ro.product.device) is retail "Станция Макс", not "Станция 2" (wiki).
		// SKU YNDX-0008; YNDX-00052/00053 are the same appearance with Zigbee.
		Retail: "Станция Макс (Android)", SKU: "YNDX-0008 / YNDX-00052 / YNDX-00053",
		Compat: "station_2",
		Colors: []string{"beige", "black", "blue", "green", "red", "turquoise", "white"},
		Icon:   "station_2_black.png",
		Icons: map[string]string{
			"beige":     "station_2_beige.png",
			"black":     "station_2_black.png",
			"blue":      "station_2_blue.png",
			"green":     "station_2_green.png",
			"red":       "station_2_red.png",
			"turquoise": "station_2_turquoise.png",
			"white":     "station_2_white.png",
		},
	},
	{
		// Allwinner R18, Android 6 — no mDNS platform, no device-tree yandex compat.
		Retail: "Станция (1-го поколения)", SKU: "YNDX-0001",
		Compat: "tulip-d1",
		Icon:   "tulip_black.png",
	},
}

var byRetail = func() map[string]*Model {
	m := map[string]*Model{}
	for i := range models {
		m[models[i].Retail] = &models[i]
	}
	return m
}()

// Longest first, so yandex,station-mini2 wins over yandex,station-mini.
var compatRules = func() []modelRule {
	var r []modelRule
	for i := range models {
		if models[i].Compat != "" {
			r = append(r, modelRule{models[i].Compat, models[i].Retail})
		}
	}
	sort.Slice(r, func(a, b int) bool { return len(r[a].substr) > len(r[b].substr) })
	return r
}()

var platformRules = func() []modelRule {
	var r []modelRule
	for i := range models {
		if models[i].Platform != "" {
			r = append(r, modelRule{models[i].Platform, models[i].Retail})
		}
	}
	sort.Slice(r, func(a, b int) bool { return len(r[a].substr) > len(r[b].substr) })
	return r
}()

var hostnameRules = func() []modelRule {
	var r []modelRule
	for i := range models {
		if models[i].Hostname != "" {
			r = append(r, modelRule{models[i].Hostname, models[i].Retail})
		}
	}
	return r
}()

type modelRule struct {
	substr string
	name   string
}

func ModelName(compat, model string) string {
	c := strings.ToLower(compat)
	for _, r := range compatRules {
		if strings.Contains(c, r.substr) {
			return r.name
		}
	}
	m := strings.ToLower(model)
	for _, r := range modelRules {
		if strings.Contains(m, r.substr) {
			return r.name
		}
	}
	return ""
}

func PlatformModel(platform string) string {
	p := strings.ToLower(strings.TrimSpace(platform))
	for _, r := range platformRules {
		if strings.Contains(p, r.substr) {
			return r.name
		}
	}
	return ""
}

func HostnameModel(hostname string) string {
	h := strings.ToLower(hostname)
	if !strings.Contains(h, "yandex") {
		return ""
	}
	for _, r := range hostnameRules {
		if strings.Contains(h, r.substr) {
			return r.name
		}
	}
	return ""
}

// modelRules match the device-tree model string; earlier entries win,
// so "station mini 2" must precede "station mini".
var modelRules = []modelRule{
	{"station micro", "Станция Лайт"},
	{"station lite 2", "Станция Лайт 2"},
	{"lite2", "Станция Лайт 2"},
	{"plum", "Станция Лайт 2"},
	{"station mini 3", "Станция Мини 3"},
	{"mini 3", "Станция Мини 3"},
	{"bergamot", "Станция Мини 3"},
	{"pickle", "Станция Мини 3 Про"},
	{"station mini 2", "Станция Мини 2"},
	{"mini 2", "Станция Мини 2"},
	{"station mini", "Станция Мини"},
	{"station midi", "Станция 2"},
	{"cucumber", "Станция Миди"},
	{"mango", "Станция Стрит"},
	{"saturn", "Умный хаб"},
	{"chiron", "Станция Дуо Макс"},
	{"orion", "Станция 3"},
	{"tulip", "Станция (1-го поколения)"},
	{"station_2", "Станция Макс (Android)"},
}

func RetailSKU(name string) string {
	if m, ok := byRetail[name]; ok {
		return m.SKU
	}
	return ""
}

func ModelColors(name string) []string {
	if m, ok := byRetail[name]; ok {
		return m.Colors
	}
	return nil
}

func ModelIcon(name string) string {
	if m, ok := byRetail[name]; ok {
		return m.Icon
	}
	return ""
}

// Colors without a verified APK icon fall back to ModelIcon.
func ModelColorIcons(name string) map[string]string {
	if m, ok := byRetail[name]; ok {
		return m.Icons
	}
	return nil
}
