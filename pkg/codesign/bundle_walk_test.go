package codesign

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"reflect"
	"testing"
)

func TestSigningWalkFilesystemOrder(t *testing.T) {
	app := testBundle(t)
	for _, name := range []string{"z", "a", "q", "sub/last", "sub/first"} {
		bundleFile(t, app, "Contents/Resources/"+name, []byte(name))
	}
	b, err := openAppBundle(app)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	const start = "Contents/Resources"
	// Obtain the independent expectation directly from held OS directory
	// handles. Sorting would change observable strip-then-seal behavior on FAT.
	var expected []string
	var enumerate func(string)
	enumerate = func(name string) {
		expected = append(expected, name)
		st, err := b.root.Lstat(name)
		if err != nil {
			t.Fatal(err)
		}
		if !st.IsDir() {
			return
		}
		f, err := b.root.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		names, readErr := f.Readdirnames(-1)
		if err := errors.Join(readErr, f.Close()); err != nil {
			t.Fatal(err)
		}
		for _, child := range names {
			enumerate(path.Join(name, child))
		}
	}
	enumerate(start)
	var got []string
	err = (signingBundleWalker{b}).WalkDir(start, func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry == nil {
			t.Fatal(entry, err)
		}
		got = append(got, name)
		return nil
	})
	if err != nil || !reflect.DeepEqual(got, expected) {
		t.Fatal("filesystem traversal order changed", got, expected, err)
	}
}

func TestSigningWalkCallbackFailures(t *testing.T) {
	for _, kind := range []string{"root-skip", "all-skip", "file-skip", "child-skip", "callback-error", "missing", "missing-skip", "read-error", "read-skip"} {
		t.Run(kind, func(t *testing.T) {
			app := testBundle(t)
			bundleFile(t, app, "Contents/Resources/sub/a", []byte("a"))
			bundleFile(t, app, "Contents/Resources/sub/b", []byte("b"))
			b, err := openAppBundle(app)
			if err != nil {
				t.Fatal(err)
			}
			defer b.close()
			start := "Contents/Resources"
			if kind == "missing" || kind == "missing-skip" {
				start = "missing"
			}
			sentinel := errors.New("callback failure")
			visits, reads, files := 0, 0, 0
			err = (signingBundleWalker{b}).WalkDir(start, func(name string, entry fs.DirEntry, err error) error {
				visits++
				if err != nil {
					reads++
					if kind == "missing" || kind == "missing-skip" {
						if entry != nil || !errors.Is(err, os.ErrNotExist) {
							t.Fatal(entry, err)
						}
					} else if name != start || entry == nil || !errors.Is(err, os.ErrClosed) {
						t.Fatal(name, entry, err)
					}
					if kind == "read-skip" || kind == "missing-skip" {
						return fs.SkipDir
					}
					return sentinel
				}
				switch kind {
				case "root-skip":
					return fs.SkipDir
				case "all-skip":
					return fs.SkipAll
				case "callback-error":
					return sentinel
				case "read-error", "read-skip":
					if err := b.root.Close(); err != nil {
						t.Fatal(err)
					}
				case "child-skip":
					if name != start {
						return fs.SkipDir
					}
				case "file-skip":
					if !entry.IsDir() {
						files++
						return fs.SkipDir
					}
				}
				return nil
			})
			wantFailure := kind == "callback-error" || kind == "missing" || kind == "read-error"
			if wantFailure && !errors.Is(err, sentinel) || !wantFailure && err != nil {
				t.Fatal(err)
			}
			wantVisits := 1
			switch kind {
			case "file-skip":
				wantVisits = 3
				if files != 1 {
					t.Fatal("continued through skipped siblings", files)
				}
			case "child-skip", "read-error", "read-skip":
				wantVisits = 2
			}
			if visits != wantVisits {
				t.Fatal(visits, wantVisits)
			}
			if (kind == "missing" || kind == "missing-skip" || kind == "read-error" || kind == "read-skip") && reads != 1 {
				t.Fatal("lost filesystem failure", reads)
			}
		})
	}
}
