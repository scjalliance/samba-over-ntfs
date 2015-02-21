package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
)

// Example of system.ntfs_acl value (don't include line breaks):
// "0sAQAEhIgAAACkAAAAAAAAABQAAAACAHQAAwAAAAAQJAD/AR8AAQUAAAAAAAUVAAAACRQ/QoLhMx
//  rMaCWD7wQAAAAQJAC/ARMAAQUAAAAAAAUVAAAACRQ/QoLhMxrMaCWD8AQAAAAQJACpABIAAQUAAA
//  AAAAUVAAAACRQ/QoLhMxrMaCWD8QQAAAEFAAAAAAAFFQAAADf5NuUwJ3lK/OGG+8cKAAABBQAAAA
//  AABRUAAAA3+TblMCd5SvzhhvsBAgAA"

var filename = flag.String("file", "", "File to process ACL")

func main() {
	flag.Parse()

	if *filename == "" {
		flag.Usage()
		os.Exit(1)
	}

	_, err := os.Stat(*filename)
	if os.IsNotExist(err) {
		log.Fatal(err)
	}
	if err != nil {
		log.Fatal("Unable to access file: ", err)
	}

	//out, err := exec.Command("getfattr", "--only-values", "-n", "system.ntfs_acl", *filename).Output()
	out, err := exec.Command("getfattr", "--only-values", "-n", "user.ntfs_acl", *filename).Output()
	if err != nil {
		log.Fatal(err)
	}

	// dump the raw value to the screen (but you should be parsing it instead of just dumping it!)
	fmt.Println(string(out))
}
