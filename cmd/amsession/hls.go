package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"sort"
	"strings"

	am "github.com/AmarnathCJD/AppleDL"
)

// Only known protocol literals are logged. Unknown server-controlled strings,
// including URLs, key data and unhandled tags, stay out of progress files.
func reportHLS(out io.Writer, m *am.HLSManifest) {
	duration := 0.0
	for _, s := range m.Segments {
		duration += s.Duration
	}
	fmt.Fprintf(out, "Playlist: variants=%d renditions=%d segments=%d maps=%d durationSeconds=%.3f endList=%t encryptionSignaled=%t unhandledTagCount=%d\n", len(m.Variants), len(m.Renditions), len(m.Segments), len(m.Maps), duration, m.EndList, m.EncryptionSignaled, len(m.UnhandledTags))
	known := []string{"mp4a.40.2", "mp4a.40.5", "mp4a.40.29", "alac", "ac-3", "ec-3", "ac-4"}
	codecs := map[string]int{}
	unknown := 0
	for _, v := range m.Variants {
		for _, codec := range strings.Split(v.Codecs, ",") {
			codec = strings.TrimSpace(codec)
			if codec == "" {
				continue
			}
			found := false
			for _, k := range known {
				if codec == k {
					codecs[k]++
					found = true
					break
				}
			}
			if !found {
				unknown++
			}
		}
	}
	for _, k := range known {
		if codecs[k] > 0 {
			fmt.Fprintf(out, "Declared codec %s: variantCount=%d\n", k, codecs[k])
		}
	}
	fmt.Fprintf(out, "Unrecognized codec declaration count: %d\n", unknown)
	for _, key := range m.Keys {
		method := "unrecognized"
		switch key.Method {
		case "NONE", "AES-128", "SAMPLE-AES", "SAMPLE-AES-CTR":
			method = key.Method
		}
		format := "unrecognized"
		switch key.Format {
		case "identity", "com.apple.streamingkeydelivery", "com.microsoft.playready", "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed":
			format = key.Format
		}
		fmt.Fprintf(out, "Key declaration: method=%s format=%s session=%t IVPresent=%t\n", method, format, key.Session, key.IV != "")
	}
	locations := map[string]int{}
	addLocation := func(raw string, ranged bool) {
		u, err := url.Parse(raw)
		if err != nil {
			locations["invalid"]++
			return
		}
		host := "unrecognized"
		switch strings.ToLower(u.Hostname()) {
		case "aod.itunes.apple.com", "audio-ssl.itunes.apple.com":
			host = strings.ToLower(u.Hostname())
		default:
			if strings.HasSuffix(strings.ToLower(u.Hostname()), ".mzstatic.com") {
				host = "mzstatic CDN"
			}
		}
		ext := "unrecognized"
		switch path.Ext(u.Path) {
		case ".mp4", ".m4a", ".m4s", ".aac", ".ts":
			ext = path.Ext(u.Path)
		}
		locations[fmt.Sprintf("hostClass=%s extension=%s ranged=%t HTTPS=%t", host, ext, ranged, u.Scheme == "https")]++
	}
	for _, s := range m.Segments {
		addLocation(s.URL, s.Range != nil)
	}
	for _, init := range m.Maps {
		addLocation(init.URL, init.Range != nil)
	}
	ordered := make([]string, 0, len(locations))
	for location := range locations {
		ordered = append(ordered, location)
	}
	sort.Strings(ordered)
	for _, location := range ordered {
		fmt.Fprintf(out, "Media resource declarations: %s count=%d\n", location, locations[location])
	}
}

// This is a diagnostic sample, not Android's playback selection algorithm.
// Inspect the root and at most three distinct direct children, without
// recursion or requests to key, init-map or segment URLs.
func inspectHLS(ctx context.Context, out io.Writer, root string, fetch func(context.Context, string) (*am.HLSManifest, error)) error {
	fmt.Fprintln(out, "Inspecting enhancedHls root playlist.")
	if u, err := url.Parse(root); err == nil {
		host := "unrecognized"
		switch strings.ToLower(u.Hostname()) {
		case "aod.itunes.apple.com", "audio-ssl.itunes.apple.com":
			host = strings.ToLower(u.Hostname())
		default:
			if strings.HasSuffix(strings.ToLower(u.Hostname()), ".mzstatic.com") {
				host = "mzstatic CDN"
			}
		}
		// A DNS hostname identifies the service, not the signed media resource.
		// Emit no path, query, userinfo or fragment. Limit to ordinary DNS text.
		dns := u.Hostname()
		validDNS := len(dns) > 0 && len(dns) <= 253
		for _, ch := range dns {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '.') {
				validDNS = false
			}
		}
		if validDNS {
			fmt.Fprintf(out, "Playlist service hostname: %s\n", dns)
		}
		fmt.Fprintf(out, "Playlist location: hostClass=%s HTTPS=%t m3u8Extension=%t pathSegments=%d queryPresent=%t\n", host, u.Scheme == "https", path.Ext(u.Path) == ".m3u8", len(strings.Split(strings.Trim(u.Path, "/"), "/")), u.RawQuery != "")
	}
	m, err := fetch(ctx, root)
	if err != nil {
		return err
	}
	reportHLS(out, m)
	children := directHLSChildren(root, m)
	fmt.Fprintf(out, "Distinct direct child playlists: %d; inspection limit: 3\n", len(children))
	for i, child := range children {
		if i == 3 {
			break
		}
		fmt.Fprintf(out, "Inspecting child playlist %d.\n", i+1)
		m, err := fetch(ctx, child)
		if err != nil {
			return err
		}
		reportHLS(out, m)
	}
	fmt.Fprintln(out, "Playlist inspection complete; declarations do not establish licensed playback or decryption.")
	return nil
}

func directHLSChildren(root string, m *am.HLSManifest) []string {
	seen := map[string]bool{root: true}
	var children []string
	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			children = append(children, u)
		}
	}
	for _, v := range m.Variants {
		add(v.URL)
	}
	for _, r := range m.Renditions {
		if r.Type == "AUDIO" {
			add(r.URL)
		}
	}
	return children
}

// Selection is explicit and diagnostic; it does not reproduce the APK's
// adaptive rendition selector. Only the root and one direct child are followed.
func selectHLSMedia(ctx context.Context, root string, index int, fetch func(context.Context, string) (*am.HLSManifest, error)) (*am.HLSManifest, error) {
	m, err := fetch(ctx, root)
	if err != nil {
		return nil, err
	}
	if len(m.Variants) == 0 && len(m.Segments) > 0 {
		if index != 0 {
			return nil, errors.New("media root requires child index 0")
		}
		return m, nil
	}
	children := directHLSChildren(root, m)
	if index < 1 || index > len(children) {
		return nil, errors.New("HLS child index is out of range")
	}
	m, err = fetch(ctx, children[index-1])
	if err != nil {
		return nil, err
	}
	if len(m.Variants) != 0 || len(m.Segments) == 0 {
		return nil, errors.New("selected HLS child is not a media playlist")
	}
	return m, nil
}

func selectHLSCodec(ctx context.Context, root, codec string, fetch func(context.Context, string) (*am.HLSManifest, error)) (*am.HLSManifest, error) {
	m, err := fetch(ctx, root)
	if err != nil {
		return nil, err
	}
	urls := map[string]bool{}
	for _, v := range m.Variants {
		for _, c := range strings.Split(v.Codecs, ",") {
			if strings.TrimSpace(c) == codec && v.URL != "" && v.URL != root {
				urls[v.URL] = true
			}
		}
	}
	if len(urls) != 1 {
		return nil, errors.New("codec selector requires one distinct matching variant URI")
	}
	for uri := range urls {
		m, err = fetch(ctx, uri)
	}
	if err != nil {
		return nil, err
	}
	if len(m.Variants) != 0 || len(m.Segments) == 0 {
		return nil, errors.New("codec variant is not a media playlist")
	}
	return m, nil
}

func acquireSelectedHLS(ctx context.Context, out io.Writer, root string, index int, codec, destination, userAgent, language string, fetch func(context.Context, string) (*am.HLSManifest, error)) error {
	var m *am.HLSManifest
	var err error
	if codec != "" {
		m, err = selectHLSCodec(ctx, root, codec, fetch)
		fmt.Fprintf(out, "Acquisition selection: declaredCodec=%s; unique matching variant.\n", codec)
	} else {
		m, err = selectHLSMedia(ctx, root, index, fetch)
		fmt.Fprintf(out, "Acquisition selection: directChild=%d; explicit diagnostic order.\n", index)
	}
	if err != nil {
		return err
	}
	reportHLS(out, m)
	var session [16]byte
	if _, err := rand.Read(session[:]); err != nil {
		return errors.New("cannot generate playback session ID")
	}
	session[6] = (session[6] & 0x0f) | 0x40
	session[8] = (session[8] & 0x3f) | 0x80
	id := fmt.Sprintf("%x-%x-%x-%x-%x", session[:4], session[4:6], session[6:8], session[8:10], session[10:])
	fmt.Fprintln(out, "Fetching selected initialization data and all segments; saved-byte limit=268435456.")
	receipt, err := am.AcquireHLS(ctx, nil, m, destination, am.HLSAcquisitionOptions{UserAgent: userAgent, Language: language, PlaybackSessionID: id})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Acquisition complete: files=%d segments=%d bytes=%d durationSeconds=%.3f encryptionSignaled=%t decrypted=%t\n", len(receipt.Files), receipt.SegmentCount, receipt.TotalBytes, receipt.DurationSeconds, receipt.EncryptionSignaled, receipt.Decrypted)
	return nil
}
