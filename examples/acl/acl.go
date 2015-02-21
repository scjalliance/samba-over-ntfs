package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"go.scj.io/samba-over-ntfs/ntfsacl"
	"go.scj.io/samba-over-ntfs/sambaacl"
)

// Example of system.ntfs_acl value (don't include line breaks):
// "0sAQAEhIgAAACkAAAAAAAAABQAAAACAHQAAwAAAAAQJAD/AR8AAQUAAAAAAAUVAAAACRQ/QoLhMx
//  rMaCWD7wQAAAAQJAC/ARMAAQUAAAAAAAUVAAAACRQ/QoLhMxrMaCWD8AQAAAAQJACpABIAAQUAAA
//  AAAAUVAAAACRQ/QoLhMxrMaCWD8QQAAAEFAAAAAAAFFQAAADf5NuUwJ3lK/OGG+8cKAAABBQAAAA
//  AABRUAAAA3+TblMCd5SvzhhvsBAgAA"

var sourceFilename = flag.String("from", "", "File to read NTFS ACL")
var destinationFilename = flag.String("to", "", "File to write Samba ACL (no write if omitted)")

func main() {
	flag.Parse()

	// FIXME: this is only for initial build so you can test this on a non-NTFS filesystem (otherwise remove entirely)
	ntfsacl.SetXattr("user.ntfs_acl")
	// FIXME: this is only for initial build so you can test this without superuser (otherwise remove entirely)
	sambaacl.SetXattr("user.NTACL")

	if sourceFilename == nil || *sourceFilename == "" {
		flag.Usage()
		os.Exit(1)
	}

	if _, err := os.Stat(*sourceFilename); err != nil {
		if os.IsNotExist(err) {
			log.Fatal(err)
		}
		log.Fatal("Unable to access source file: ", err)
	}

	ntfsRawACL, err := ntfsacl.Read(*sourceFilename)
	if err != nil {
		log.Fatal(err)
	}

	if destinationFilename == nil || *destinationFilename == "" {
		// dump the raw value to the screen (but you should be parsing it instead of just dumping it!)
		fmt.Println(string(ntfsRawACL))
		os.Exit(0)
	}

	if _, err := os.Stat(*destinationFilename); err != nil {
		if os.IsNotExist(err) {
			log.Fatal(err)
		}
		log.Fatal("Unable to access destination file: ", err)
	}

	if err := sambaacl.Write(*destinationFilename, ntfsRawACL); err != nil {
		log.Fatal(err)
	}
}
