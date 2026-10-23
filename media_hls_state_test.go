package applemusic

import (
	"reflect"
	"strings"
	"testing"
)

func TestHLSSegmentStateSnapshots(t *testing.T) {
	input := `#EXTM3U
#EXT-X-MEDIA-SEQUENCE:40
#EXT-X-DISCONTINUITY-SEQUENCE:2
#EXT-X-SESSION-KEY:METHOD=SAMPLE-AES,URI="skd://session",KEYFORMAT="com.apple.streamingkeydelivery"
#EXT-X-MAP:URI="clear-init.mp4",BYTERANGE="10@0"
#EXT-X-KEY:METHOD=SAMPLE-AES,URI="skd://first",KEYFORMAT="com.apple.streamingkeydelivery",KEYFORMATVERSIONS="1/2"
#EXT-X-KEY:METHOD=AES-128,URI="key.bin",IV=0x01
#EXTINF:1,
#EXT-X-BYTERANGE:5@10
full.mp4
#EXT-X-KEY:METHOD=SAMPLE-AES,URI="skd://second",KEYFORMAT="com.apple.streamingkeydelivery"
#EXT-X-MAP:URI="encrypted-init.mp4"
#EXT-X-DISCONTINUITY
#EXT-X-GAP
#EXTINF:2,
#EXT-X-BYTERANGE:7
full.mp4
#EXT-X-KEY:METHOD=NONE
#EXTINF:3,
clear.mp4
#EXT-X-ENDLIST
`
	m, err := ParseHLS(strings.NewReader(input), "https://audio.mzstatic.com/master.m3u8")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Keys) != 5 || m.Keys[1].Versions != "1/2" || m.Keys[3].Versions != "1" {
		t.Fatal("key versions missing")
	}
	for i, want := range [][]int{{1, 2}, {3, 2}, nil} {
		if !reflect.DeepEqual(m.Segments[i].KeyIndices, want) {
			t.Fatalf("wrong key snapshot at segment %d", i)
		}
	}
	if len(m.Maps[0].KeyIndices) != 0 || !reflect.DeepEqual(m.Maps[1].KeyIndices, []int{3, 2}) {
		t.Fatal("wrong initialization key snapshot")
	}
	for i, s := range m.Segments {
		if s.Sequence != int64(40+i) || *s.MapIndex != []int{0, 1, 1}[i] || s.DiscontinuitySequence != []int64{2, 3, 3}[i] || s.Gap != (i == 1) {
			t.Fatal("wrong segment state")
		}
	}
	if *m.Segments[0].Range != (HLSByteRange{10, 5}) || *m.Segments[1].Range != (HLSByteRange{15, 7}) || m.Segments[2].Range != nil {
		t.Fatal("wrong resolved ranges")
	}
	m.Segments[1].KeyIndices[0] = 99
	if m.Segments[0].KeyIndices[0] != 1 || m.Maps[1].KeyIndices[0] != 3 {
		t.Fatal("key snapshots share mutable storage")
	}
}

func TestHLSRejectsAmbiguousSegmentState(t *testing.T) {
	for i, body := range []string{
		"#EXT-X-MAP:URI=\"init.mp4\",BYTERANGE=\"5\"\n#EXTINF:1,\ns.mp4\n",
		"#EXTINF:1,\n#EXT-X-BYTERANGE:5\ns.mp4\n",
		"#EXTINF:1,\n#EXT-X-BYTERANGE:5@0\ns.mp4\n#EXTINF:1,\n#EXT-X-BYTERANGE:5\nother.mp4\n",
		"#EXTINF:1,\n#EXT-X-BYTERANGE:5@0\ns.mp4\n#EXTINF:1,\ns.mp4\n#EXTINF:1,\n#EXT-X-BYTERANGE:5\ns.mp4\n",
		"#EXTINF:1,\n#EXT-X-BYTERANGE:5@9223372036854775802\ns.mp4\n#EXTINF:1,\n#EXT-X-BYTERANGE:5\ns.mp4\n",
		"#EXT-X-MEDIA-SEQUENCE:9223372036854775807\n#EXTINF:1,\ns.mp4\n#EXTINF:1,\ns.mp4\n",
		"#EXT-X-MEDIA-SEQUENCE:1\n#EXT-X-MEDIA-SEQUENCE:2\n#EXTINF:1,\ns.mp4\n",
		"#EXTINF:1,\ns.mp4\n#EXT-X-MEDIA-SEQUENCE:1\n",
		"#EXT-X-DISCONTINUITY-SEQUENCE:9223372036854775807\n#EXT-X-DISCONTINUITY\n#EXTINF:1,\ns.mp4\n",
		"#EXT-X-DISCONTINUITY\n#EXT-X-DISCONTINUITY-SEQUENCE:1\n#EXTINF:1,\ns.mp4\n",
		"#EXT-X-KEY:METHOD=NONE,URI=\"bad\"\n#EXTINF:1,\ns.mp4\n",
		"#EXT-X-SESSION-KEY:METHOD=NONE\n#EXTINF:1,\ns.mp4\n",
		"#EXTINF:1,\ns.mp4\n#EXT-X-GAP\n",
	} {
		if _, err := ParseHLS(strings.NewReader("#EXTM3U\n"+body), "https://audio.mzstatic.com/master.m3u8"); err == nil {
			t.Fatalf("accepted invalid state case %d", i)
		}
	}
}
