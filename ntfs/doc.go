/*
Package ntfs describes a set of data accessors for NTFS-formatted binary data
that enable conversion to the security descriptor types defined in the ntsd
package.

It is possible that the same wire format use by NTFS is also used in the Server
Message Block protocol or for in-memory representation within Windows, but that
has not yet been validated by the package authors. If it can be demonstrated
that the wire format is used in places other than the NTFS it may be
appropriate to rename this package.

File security descriptor access is currently possible on Linux build targets
through the use of the ntfs-3g libary.

File security descriptor access on Windows build targets is currently under
investigation.
*/
package ntfs
