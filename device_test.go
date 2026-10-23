package applemusic

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func deviceFixture() DeviceMetadata {
	return DeviceMetadata{
		Manufacturer: "Google", Model: "Pixel9", PlatformName: "Android",
		PlatformVersion: "15", BuildVersion: "1606", HardwarePlatform: "x64",
		BundleIdentifier: "musicAndroid", BundleName: "Music", BundleVersion: "7.0.0",
		UserAgent: "Music/7.0.0 Android/15 model/GooglePixel9 build/1606 (dt:66) AMS/1",
		DeviceID:  "SYNTHETIC-DEVICE", StableID: "SYNTHETIC-STABLE", Language: "en-US",
	}
}

func TestClientInfoMatchesCapturedPublicLookup(t *testing.T) {
	// Independently captured from e7.m on the emulator; IDs were not captured.
	want := "<Google> <Android;15;Android/15 build/1606 maker/Google model/Pixel9 FW/x64> <com.apple.AuthKitAndroid/1.0 (Music/7.0.0)>"
	m := deviceFixture()
	got, err := m.ClientInfo()
	if err != nil || got != want {
		t.Fatalf("client-info mismatch: %q, %v", got, err)
	}
	h, err := m.IdMSHeaders()
	if err != nil || len(h) != 9 || h.Get("X-Apple-I-Client-Bundle-Id") != "com.apple.AuthKitAndroid" || h.Get("X-Apple-I-Proxied-Bundle-Id") != "musicAndroid" {
		t.Fatal("base bundle headers differ")
	}
	if h.Get("X-AppleId-Device-UDID") != m.DeviceID || h.Get("X-MME-Device-Id") != m.DeviceID || h.Get("X-Apple-I-Stable-Id") != m.StableID {
		t.Fatal("device identifiers changed or confused")
	}
	if h.Get("X-Apple-I-MD-RInfo") != "0" || h.Get("Accept-Language") != "en-US" || h.Get("User-Agent") != m.UserAgent {
		t.Fatal("metadata mapping differs")
	}
	m.BuildType = 2
	seed, err := m.IdMSHeaders()
	if err != nil || seed.Get("X-Apple-I-88CC-99DE-EE63-2736") != "true" || h.Get("X-Apple-I-88CC-99DE-EE63-2736") != "" {
		t.Fatal("build-type condition or map independence differs")
	}
}

func TestClientInfoNativeWhitespaceRules(t *testing.T) {
	m := deviceFixture()
	m.Manufacturer = " G\to\no\vg\fl\re "
	m.Model = "Pixel\u00a09" // Native removes ASCII whitespace only.
	m.BundleName = " Music Player "
	m.BundleVersion = " 7.0.0 "
	m.HardwarePlatform = ""
	got, err := m.ClientInfo()
	want := "<Google> <Android;15;Android/15 build/1606 maker/Google model/Pixel\u00a09> <com.apple.AuthKitAndroid/1.0 ( Music Player / 7.0.0 )>"
	if err != nil || got != want {
		t.Fatalf("native cleanup mismatch: %q, %v", got, err)
	}
	m.Manufacturer, m.Model = "", ""
	got, err = m.ClientInfo()
	if err != nil || !strings.HasPrefix(got, "<> <Android;") || !strings.Contains(got, " maker/ model/>") {
		t.Fatal("invented fallback for present empty strings")
	}
}

func TestMetadataRejectsInvalidHeadersWithoutLeakingValues(t *testing.T) {
	for name, change := range map[string]func(*DeviceMetadata){
		"device injection":   func(m *DeviceMetadata) { m.DeviceID = "SECRET\r\nInjected: value" },
		"stable empty":       func(m *DeviceMetadata) { m.StableID = "" },
		"device trimming":    func(m *DeviceMetadata) { m.DeviceID = " SECRET " },
		"bundle injection":   func(m *DeviceMetadata) { m.BundleName = "SECRET\n" },
		"language control":   func(m *DeviceMetadata) { m.Language = "SECRET\t" },
		"component nul":      func(m *DeviceMetadata) { m.Model = "SECRET\x00" },
		"component del":      func(m *DeviceMetadata) { m.Model = "SECRET\x7f" },
		"component encoding": func(m *DeviceMetadata) { m.Model = "SECRET\xff" },
		"field bound":        func(m *DeviceMetadata) { m.DeviceID = strings.Repeat("S", 4097) },
		"formatted bound": func(m *DeviceMetadata) {
			m.PlatformName = strings.Repeat("P", 4096)
			m.Manufacturer = strings.Repeat("M", 4096)
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := deviceFixture()
			change(&m)
			h, err := m.IdMSHeaders()
			if h != nil || !errors.Is(err, ErrDeviceMetadata) || strings.Contains(err.Error(), "SECRET") {
				t.Fatal("invalid metadata accepted or exposed")
			}
		})
	}
	m := deviceFixture()
	for _, value := range []any{m, &m} {
		if got := fmt.Sprintf("%v %+v %#v", value, value, value); strings.Contains(got, "SYNTHETIC") {
			t.Fatal("formatting exposed an identifier")
		}
	}
}
