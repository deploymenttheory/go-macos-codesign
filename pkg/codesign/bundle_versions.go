package codesign

import (
	"context"
	"io/fs"
	"os"
)

// Unselected versions are not signed or cryptographically inspected. Inventory
// their physical members without following links so that writes cannot alter
// them through a hard link and they share the tree's path and size budgets.
func (b *appBundle) inventoryOtherVersions(ctx context.Context, scope *bundleScan, prefix string) error {
	for _, version := range b.versions {
		if version == b.version {
			continue
		}
		if err := scope.addChild(); err != nil {
			return err
		}
		start := "Versions/" + version
		if err := fs.WalkDir(b.root.FS(), start, func(name string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if name == start {
				return nil
			}
			if err := scope.entry(prefix + name); err != nil {
				return err
			}
			if d.IsDir() || d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			st, err := d.Info()
			if err != nil {
				return err
			}
			if !st.Mode().IsRegular() {
				return unsupported("non-regular framework version member: " + name)
			}
			if err := scope.regularFile(prefix+name, st); err != nil {
				return err
			}
			if st.Size() > maxFileSize-scope.bytes {
				return unsupported("bundle input exceeds 1 GiB")
			}
			scope.bytes += st.Size()
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
