package acceptance

import (
	"os"
	"testing"
	"time"
)

func executableDirectoryAccess(t *testing.T, before, after, neighbour os.FileInfo, accessed bool, started, finished time.Time) map[string]any {
	t.Helper()
	at, other := writerAccess(after), writerAccess(neighbour)
	if accessed {
		for _, value := range []time.Time{at, other} {
			if value.Before(started) || value.After(finished) {
				t.Fatalf("access %v outside [%v, %v]", value, started, finished)
			}
		}
		if !os.SameFile(before, after) && !at.After(other) {
			t.Fatal("replacement access did not follow source")
		}
	} else if !at.Equal(writerAccess(before)) || !other.Equal(writerAccess(before)) {
		t.Fatal("untouched access changed")
	}
	if !writerBirth(neighbour).Equal(writerBirth(before)) {
		t.Fatal("neighbour creation time changed")
	}
	if os.SameFile(before, after) && !writerBirth(after).Equal(writerBirth(before)) {
		t.Fatal("uncommitted creation time changed")
	}
	return map[string]any{"before": writerAccess(before), "after": at, "neighbour": other, "accessed": accessed, "native_accessed": accessed, "known_difference": false}
}
