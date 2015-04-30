package mirrorfs

import (
	"os"
	"syscall"
	"time"

	"bazil.org/fuse"
)

func direntOSToFuse(fi os.FileInfo, name string) fuse.Dirent {
	st := fi.Sys().(*syscall.Stat_t)
	return fuse.Dirent{
		Inode: st.Ino,
		Type:  fuse.DirentType(st.Mode & syscall.S_IFMT >> 12), // See definition of fuse.DirentType for context
		Name:  name,
	}
}

func timespecToTime(ts syscall.Timespec) time.Time {
	return time.Unix(int64(ts.Sec), int64(ts.Nsec))
}
