// Recursively skate a directory tree and provide statistics and test for parse
// failure
package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go.scj.io/samba-over-ntfs/ntfs"
	"go.scj.io/samba-over-ntfs/samba"
)

const (
	modeSamba = "samba"
	modeNTFS  = "ntfs"
	modeSDDL  = "sddl"

	encBase64 = "b64"
	encHex    = "hex"
)

var (
	start      time.Time
	iChan      chan int
	noop       = flag.Bool("noop", false, "Skip the actual parsing phase; just test the speed of skating")
	workers    = flag.Int("workers", runtime.NumCPU(), "How many concurrent workers to do the parsing?")
	interval   = flag.Int("interval", 1, "Time in seconds between statistical output (0 = never)")
	path       = flag.String("path", "", "File/directory path to read ACL source data from")
	source     *string
	xattrNTFS  *string
	xattrSamba *string
)

func main() {
	if runtime.GOOS == "windows" {
		*source = "ntfs"
	} else {
		source = flag.String("source", "auto", "Source is (ntfs|samba|auto)")
		xattrNTFS = flag.String("xattrNTFS", "system.ntfs_acl", "Extended attribute to read from NTFS")
		xattrSamba = flag.String("xattrSamba", "security.NTACL", "Extended attribute to read from Samba")
	}

	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Parse()

	if *path == "" {
		flag.Usage()
		log.Fatal("Requires value for -path")
	}

	if *xattrNTFS == "" {
		flag.Usage()
		log.Fatal("-xattrNTFS must not be empty")
	}

	if *xattrSamba == "" {
		flag.Usage()
		log.Fatal("-xattrSamba must not be empty")
	}

	*source = strings.ToLower(*source)
	if *source != "auto" && *source != "ntfs" && *source != "samba" {
		flag.Usage()
		log.Fatal("-source must be one of: ntfs, samba, auto")
	}

	iChan = counter()
	paths := workerPool()
	start = time.Now()

	err := filepath.Walk(*path, func(fp string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		paths <- fp
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	end := time.Now()
	entries := <-iChan
	timeDiff := float32(end.Sub(start)) / float32(time.Second)
	eps := float32(entries) / timeDiff
	log.Printf("Reviewed %d files and directories.\n", entries)
	log.Printf("Time taken: %.2f seconds.", timeDiff)
	log.Printf("Speed: %.2f entries per second.", eps)
}

func counter() chan int {
	iChan := make(chan int)
	ticker := &time.Ticker{}
	if *interval > 0 {
		ticker = time.NewTicker(time.Second * time.Duration(*interval))
	}
	go func() {
		i := 0
		for {
			select {
			case iChan <- i:
				i++
			case <-ticker.C:
				timeDiff := float32(time.Now().Sub(start)) / float32(time.Second)
				eps := float32(i) / timeDiff
				timeDiffPlural := "s"
				if int(timeDiff+0.5) == 1 {
					timeDiffPlural = " "
				}
				log.Printf(">> % 12d entries | % 6.0f second%s elapsed | % 10.2f entries/second\n", i, timeDiff, timeDiffPlural, eps)
			}
		}
	}()
	return iChan
}

func workerPool() chan string {
	paths := make(chan string)               // how our workers get the file paths to process
	pool := make(chan interface{}, *workers) // how many worker seats available?
	go func() {
		for {
			pool <- nil // take a worker seat
			go func() { // the worker itself
				defer func() { <-pool }() // give back the worker seat when done
				process(<-paths)
			}()
		}
	}()
	return paths
}

func process(fp string) {
	<-iChan
	if !*noop {
		var (
			sdBytes []byte
			err     error
		)
		if *source == "ntfs" || *source == "auto" {
			if runtime.GOOS == "windows" {
				// can't specify/override xattr in Windows
				sdBytes, err = ntfs.ReadFileRawSD(fp)
			} else {
				sdBytes, err = ntfs.ReadFileAttribute(fp, *xattrNTFS)
			}
			if err == nil {
				sd := ntfs.UnmarshalSecurityDescriptor(sdBytes)
				sd.SDDL() // should we be running this at all?  does it prove anything for our testing?
				return
			}
			if os.IsNotExist(err) {
				// I've noticed occasional "unsupported reparse point" errors causing
				// this (but maybe other things, too) when skating through via NTFS-3G
				// from Linux on my laptop when having a secondary drive (NTFS) mounted,
				// which appears to the userspace as a broken symlink
				return
			}
			log.Printf("Error on NTFS file %s: %s\n", fp, err)
		}
		if *source == "samba" || (*source == "auto" && sdBytes == nil) {
			sdBytes, err = samba.ReadFileAttribute(fp, *xattrSamba)
			if err == nil {
				sd := samba.UnmarshalXAttr(sdBytes)
				sd.SDDL() // should we be running this at all?  does it prove anything for our testing?
				return
			}
			if os.IsNotExist(err) {
				// FIXME: shouldn't we care about this error?  this blind return needs to be thought about...
				return
			}
			// FIXME: should we complain that we got to this point?
		}
		// something went wrong?  file neither samba nor ntfs?
		log.Printf("No action on %s\n", fp)
	}
	return
}
