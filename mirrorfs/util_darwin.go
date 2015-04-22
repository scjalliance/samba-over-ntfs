package mirrorfs

import (
	"os"
	"syscall"
	"time"

	"bazil.org/fuse"
)

func attrOSToFuse(f *os.File, a *fuse.Attr) {
	fi, err := f.Stat()
	if err != nil {
		// TODO: Decide how to handle an error here
		return
	}

	st := fi.Sys().(*syscall.Stat_t)

	a.Inode = st.Ino
	a.Size = uint64(fi.Size())
	a.Blocks = uint64(st.Blocks)
	a.Atime = timespecToTime(st.Atimespec)
	a.Mtime = fi.ModTime()
	a.Ctime = timespecToTime(st.Ctimespec)
	a.Crtime = timespecToTime(st.Birthtimespec)
	a.Mode = fi.Mode()
	a.Nlink = uint32(st.Nlink)
}

func timespecToTime(ts syscall.Timespec) time.Time {
	return time.Unix(int64(ts.Sec), int64(ts.Nsec))
}
