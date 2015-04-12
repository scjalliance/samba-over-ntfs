package mirrorfs

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
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

	if flag.NArg() != 2 {
		Usage()
		os.Exit(2)
	}

	path := flag.Arg(0)
	mountpoint := flag.Arg(1)

	go func() {
		for s := range signalChan {
			switch s {
			case syscall.SIGHUP:
				// reload config?  we're not actually subscribed to this
			default:
				fmt.Printf("Caught a %s signal, closing.\n", s)
				fuse.Unmount(mountpoint)
				os.Exit(1)
			}
		}
	}()
}

func mount(path, mountpoint string) {
	file, err := os.Open(path)

	if err != nil {
		// TODO: Handle the error
	}

	c, err := fuse.Mount(
		mountpoint,
		fuse.FSName("helloworld"),
		fuse.Subtype("hellofs"),
		fuse.LocalVolume(),
		fuse.VolumeName("Hello world!"),
	)

	if err != nil {
		log.Fatal(err)
	}

	defer fuse.Unmount(mountpoint)
	defer c.Close()

	err = fs.Serve(c, FS{file: file})
	if err != nil {
		log.Fatal(err)
	}

	// check if the mount process has an error to report
	<-c.Ready
	if err := c.MountError; err != nil {
		log.Fatal(err)
	}
}
