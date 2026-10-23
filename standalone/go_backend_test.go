package standalone

import (
	"context"
	"testing"
)

func TestDefaultRuntimeUsesEmbeddedGoImages(t *testing.T) {
	v, err := newGoVM()
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	if v.goMachine == nil {
		t.Fatal("default runtime uses a native backend")
	}
	path := v.string("/adi")
	defer v.free(path)
	if code, err := v.call(context.Background(), "nf92ngaK92", path); err != nil || code != 0 {
		t.Fatalf("embedded device initialization failed: status=%d error=%v", code, err)
	}
}
