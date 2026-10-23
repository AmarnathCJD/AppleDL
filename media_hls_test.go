package applemusic

import (
	"strings"
	"testing"
)

func TestHLSMasterAndEncryptedMedia(t *testing.T) {
	master := "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"audio\",NAME=\"English\",URI=\"audio.m3u8\"\n#EXT-X-SESSION-KEY:METHOD=SAMPLE-AES,URI=\"skd://fixture-key\",KEYFORMAT=\"com.apple.streamingkeydelivery\"\n#EXT-X-STREAM-INF:BANDWIDTH=256000,CODECS=\"mp4a.40.2,avc1.4d401f\",AUDIO=\"audio\"\nsub/main.m3u8\n"
	m, err := ParseHLS(strings.NewReader(master), "https://audio.mzstatic.com/base/master.m3u8")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Variants) != 1 || m.Variants[0].URL != "https://audio.mzstatic.com/base/sub/main.m3u8" || m.Variants[0].Codecs != "mp4a.40.2,avc1.4d401f" || !m.EncryptionSignaled || !m.Keys[0].Session || len(m.Renditions) != 1 {
		t.Fatal("lost master inventory")
	}
	media := "#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:3\n#EXT-X-MAP:URI=\"full.mp4\",BYTERANGE=\"100@0\"\n#EXT-X-KEY:METHOD=AES-128,URI=\"key.bin\",IV=0x1234\n#EXTINF:3.25,\n#EXT-X-BYTERANGE:200@100\nfull.mp4\n#EXT-X-KEY:METHOD=NONE\n#EXTINF:2,\nclear.m4a\n#EXT-X-FOO:bar\n#EXT-X-ENDLIST\n"
	m, err = ParseHLS(strings.NewReader(media), "https://audio.mzstatic.com/base/media.m3u8")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Segments) != 2 || m.Segments[0].Duration != 3.25 || m.Segments[0].ByteRange != "200@100" || len(m.Maps) != 1 || m.Maps[0].ByteRange != "100@0" || !m.EncryptionSignaled || m.Keys[1].Method != "NONE" || m.MediaSequence != 3 || !m.EndList || len(m.UnhandledTags) != 1 {
		t.Fatal("lost media inventory")
	}
}

func TestHLSRejectsIncompleteAndBoundedInput(t *testing.T) {
	cases := []string{
		"not hls", "#EXTM3U\n", "#EXTM3U\n#EXTINF:2,\n", "#EXTM3U\nfile.m4a\n",
		"#EXTM3U\n#EXTINF:NaN,\nx.m4a\n", "#EXTM3U\n#EXTINF:2,\nhttp://evil.test/file\n",
		"#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=2,CODECS=\"unterminated\nx.m3u8\n",
		"#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=2,BANDWIDTH=3\nx.m3u8\n",
		"#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=2\nx.m3u8\n#EXTINF:2,\nx.m4a\n",
		"#EXTM3U\n#EXT-X-KEY:METHOD=AES-128\n#EXTINF:2,\nx.m4a\n",
		"#EXTM3U\n#EXTINF:2,\n#EXT-X-BYTERANGE:2@9223372036854775807\nx.m4a\n",
		"#EXTM3U\n" + strings.Repeat("# comment\n", maxResponseBytes/10+1),
		"#EXTM3U\n#" + strings.Repeat("x", 128<<10),
	}
	for i, input := range cases {
		if _, err := ParseHLS(strings.NewReader(input), "https://audio.mzstatic.com/master.m3u8"); err == nil {
			t.Fatalf("accepted malformed case %d", i)
		}
	}
}
