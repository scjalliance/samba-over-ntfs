package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"go.scj.io/samba-over-ntfs/mirrorfs"
)

var progName = filepath.Base(os.Args[0])

var usage = func() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", progName)
	fmt.Fprintf(os.Stderr, "  %s SOURCEPATH MOUNTPOINT\n", progName)
	flag.PrintDefaults()
}

func main() {
	log.SetFlags(0)
	log.SetPrefix(progName + ": ")

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, os.Kill, syscall.SIGQUIT)

	flag.Usage = usage
	flag.Parse()

	path := flag.Arg(0)
	mountpoint := flag.Arg(1)

	if len(path) == 0 || len(mountpoint) == 0 {
		usage()
		os.Exit(2)
	}

	go func() {
		for s := range signalChan {
			switch s {
			case syscall.SIGHUP:
				// reload config?  we're not actually subscribed to this
			default:
				fmt.Printf("\nCaught a %s signal, closing.\n", s)
				mirrorfs.Unmount(mountpoint)
				os.Exit(1)
			}
		}
	}()

	if err := mirrorfs.Mount(path, mountpoint, "samba-over-ntfs", "samba-over-ntfs", "samba-over-ntfs", NewFS); err != nil {
		log.Fatal(err)
	}
}
