package mirrorfs

import (
	"os"
	"path/filepath"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

type NodeCreator func(*os.File) (fs.FS, error)

func Mount(path, mountpoint string, fsName string, subtype string, volumeName string, creator NodeCreator) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	mountpoint, err = filepath.Abs(mountpoint)
	if err != nil {
		return err
	}
	path = filepath.Clean(path)
	mountpoint = filepath.Clean(mountpoint)
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	root, err := creator(file)
	if err != nil {
		return err // FIXME: Correct error response?
	}

	c, err := fuse.Mount(
		mountpoint,
		fuse.FSName(fsName),
		fuse.Subtype(subtype),
		fuse.LocalVolume(),
		fuse.VolumeName(volumeName),
	)
	if err != nil {
		return err
	}

	defer fuse.Unmount(mountpoint)
	defer c.Close()

	err = fs.Serve(c, root)
	if err != nil {
		return err
	}

	// check if the mount process has an error to report
	<-c.Ready
	if err := c.MountError; err != nil {
		return err
	}
	return nil
}

func Unmount(mountpoint string) {
	fuse.Unmount(mountpoint)
}
