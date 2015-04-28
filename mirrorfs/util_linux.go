package mirrorfs

import (
	"os"
	"syscall"
	"unsafe"

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

const (
	listXAttrSize = 10000
)

/*
func getXAttrOSToFuse(f *os.File) ([]byte, error) {
	fd := int(f.Fd())
	length, err := fgetxattr(fd, nil) // Get the length of the xattr
	if err != nil {
		return nil, err
	}
	for i := 0; i < 2; i++ {
		if length == 0 {
			break
		}
		buffer := make([]byte, length)
		length, err = fgetxattr(fd, buffer[:]) // Get the xattr bytes
		switch err {
		case nil:
			return buffer, nil // Success
		case syscall.ERANGE:
			continue // The size of the list increased between the two calls to flistxattr. Try again with the new length.
		default:
			return nil, err // Some other error
		}
	}
	return nil, err // No XAttrs
}
*/

func getFileXAttr(f *os.File, attr string, size uint32, position uint32) (xattr []byte, err error) {
	// Note: position is always zero for linux build targets
	fd := int(f.Fd())
	length, err := fgetxattr(fd, attr, nil) // Get the length of the xattr
	if err != nil {
		return
	}
	if size == 0 {
		// By specifying a size of 0, the caller indicates that they only want the
		// length of the xattr, not the xattr itself. This is typically used
		// by the caller to allocate an appropriately sized block of memory.
		//
		// Allocating a chunk of memory like this for the sole purpose of having its
		// length measureed later on in the API is a very poor way to communicate
		// the length of the xattr, but that's what the bazil fuse library
		// currently expects of us.
		return make([]byte, length), nil
	}
	for i := 0; i < 5; i++ {
		buffer := make([]byte, length)
		newLength, err := fgetxattr(fd, attr, buffer) // Get the xattr bytes
		if newLength > int(size) {
			return nil, fuse.ERANGE
		}
		if err == nil {
			// Success
			// newLength could be less than len(buffer), so it's important to slice it to the correct length
			return buffer[:newLength], nil
		}
		if err == syscall.ERANGE {
			if newLength <= length {
				// ERANGE should never be returned when there is sufficient room in the
				// buffer. If it does the underlying file system is
				// probably misbehaving. Bail with ENOTSUP.
				// TODO: Consider panicking instead
				return nil, fuse.ENOTSUP
			}
			if i < 2 {
				// The size of the xattr increased between the two calls to fgetxattr. Try again with the new length.
				length = newLength
			} else {
				// The size of the xattr is increasing faster than our calls to fgetxattr. Try anticipating the needed buffer size.
				length += (newLength - length) * i
			}
			continue
		}
		return nil, err // Some other error
	}
	return nil, fuse.ERANGE // Too many ERANGE errors (should be an exceedingly rare case)
}

func listFileXAttr(f *os.File, size uint32, position uint32) (xattr []byte, err error) {
	// Note: position is always zero for linux build targets
	fd := int(f.Fd())
	length, err := flistxattr(fd, nil) // Get the length of the xattr
	if err != nil {
		return
	}
	if size == 0 {
		// By specifying a size of 0, the caller indicates that they only want the
		// length of the xattr list, not the list itself. This is typically used
		// by the caller to allocate an appropriately sized block of memory.
		//
		// Allocating a chunk of memory like this for the sole purpose of having its
		// length measureed later on in the API is a very poor way to communicate
		// the length of the xattr list, but that's what the bazil fuse library
		// currently expects of us.
		return make([]byte, length), nil
	}
	for i := 0; i < 5; i++ {
		buffer := make([]byte, length)
		newLength, err := flistxattr(fd, buffer) // Get the xattr list bytes
		if newLength > int(size) {
			return nil, fuse.ERANGE
		}
		if err == nil {
			// Success
			// newLength could be less than len(buffer), so it's important to slice it to the correct length
			return buffer[:newLength], nil
		}
		if err == syscall.ERANGE {
			if newLength <= length {
				// ERANGE should never be returned when there is sufficient room in the
				// buffer. If it does the underlying file system is
				// probably misbehaving. Bail with ENOTSUP.
				// TODO: Consider panicking instead
				return nil, fuse.ENOTSUP
			}
			if i < 2 {
				// The size of the list increased between the two calls to flistxattr. Try again with the new length.
				length = newLength
			} else {
				// The size of the list is increasing faster than our calls to flistxattr. Try anticipating the needed buffer size.
				length += (newLength - length) * i
			}
			continue
		}
		return nil, err // Some other error
	}
	return nil, fuse.ERANGE // Too many ERANGE errors (should be an exceedingly rare case)
}

func fgetxattr(fd int, attr string, dest []byte) (sz int, err error) {
	var _p0 *byte
	_p0, err = syscall.BytePtrFromString(attr)
	if err != nil {
		return
	}
	var _p1 unsafe.Pointer
	if len(dest) > 0 {
		_p1 = unsafe.Pointer(&dest[0])
	} else {
		_p1 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := syscall.Syscall6(syscall.SYS_FGETXATTR, uintptr(fd), uintptr(unsafe.Pointer(_p0)), uintptr(_p1), uintptr(len(dest)), 0, 0)
	//use(unsafe.Pointer(_p0))
	sz = int(r0)
	if e1 != 0 {
		err = e1
	}
	return
}

// http://man7.org/linux/man-pages/man2/listxattr.2.html
func flistxattr(fd int, dest []byte) (sz int, err error) {
	var _p0 unsafe.Pointer
	if len(dest) > 0 {
		_p0 = unsafe.Pointer(&dest[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := syscall.Syscall(syscall.SYS_FLISTXATTR, uintptr(fd), uintptr(_p0), uintptr(len(dest)))
	//use(unsafe.Pointer(_p0))
	sz = int(r0)
	if e1 != 0 {
		err = e1
	}
	return
}

var _zero uintptr

// use is a no-op, but the compiler cannot see that it is.
// Calling use(p) ensures that p is kept live until that point.
//go:noescape
//func use(p unsafe.Pointer)
