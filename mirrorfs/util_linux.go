package mirrorfs

import (
	"os"
	"syscall"

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
	a.Atime = timespecToTime(st.Atim)
	a.Mtime = fi.ModTime()
	a.Ctime = timespecToTime(st.Mtim)
	// Note: Linux does not store the Crtime, but Atime often happens to be the
	//       creation time of a file when the file system is mounted with the
	//       noatime flag. Should we return it here? Perhaps only if it is the
	//       least of all three values?
	//a.Crtime = a.Atime
	a.Mode = fi.Mode()
	a.Nlink = uint32(st.Nlink) // FIXME: Consider what we should do if Nlink doesn't fit in 32 bits
	a.Uid = st.Uid
	a.Gid = st.Gid
}
