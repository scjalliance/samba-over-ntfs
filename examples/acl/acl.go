package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"go.scj.io/samba-over-ntfs/ntfs"
	"go.scj.io/samba-over-ntfs/ntsecurity"
	"go.scj.io/samba-over-ntfs/samba"
)

// Example of system.ntfs_acl value (don't include line breaks):
// "0sAQAEhIgAAACkAAAAAAAAABQAAAACAHQAAwAAAAAQJAD/AR8AAQUAAAAAAAUVAAAACRQ/QoLhMx
//  rMaCWD7wQAAAAQJAC/ARMAAQUAAAAAAAUVAAAACRQ/QoLhMxrMaCWD8AQAAAAQJACpABIAAQUAAA
//  AAAAUVAAAACRQ/QoLhMxrMaCWD8QQAAAEFAAAAAAAFFQAAADf5NuUwJ3lK/OGG+8cKAAABBQAAAA
//  AABRUAAAA3+TblMCd5SvzhhvsBAgAA"

const (
	modeSamba = "samba"
	modeNTFS  = "ntfs"
	modeSDDL  = "sddl"
)

const (
	encBase64 = "b64"
	encHex    = "hex"
)

var (
	sourceFilename       string
	destinationFilename  string
	sourceAttribute      string
	destinationAttribute string
	value                string
	inputMode            string
	outputMode           string
	encoding             string
	raw                  bool
)

const (
	valueUsage                = "Value to be used as ACL source data"
	sourceFilenameUsage       = "File to read ACL source data from"
	destinationFilenameUsage  = "File to write ACL output data to (outputs to stdout if omitted)"
	sourceAttributeUsage      = "Name of extended attribute in source file"
	destinationAttributeUsage = "Name of extended attribute in destination file"
	inputModeUsage            = "Format of input data (samba, ntfs, sddl)"
	outputModeUsage           = "Format of output data (samba, ntfs, sddl)"
	encodingUsage             = "Encoding of output data (b64, hex)"
	rawUsage                  = "Performs a raw copy of the bytes instead of interpreting them"
	shorthand                 = " (shorthand)"
	usage                     = `Usage of acl.exe:
  -v, -value:          Value to be used as ACL attribute data
  -f, -from:           File to read ACL attribute from
  -t, -to:             File to write ACL attribute to (stdout if omitted)
  -sa:                 Name of extended attribute in source file
  -da:                 Name of extended attribute in destination file
  -i, -in, -input:     Format of input data (samba, ntfs, sddl)
  -o, -out, -output:   Format of output data (samba, ntfs, sddl)
  -e, -enc, -encoding: Encoding of output data (b64 [default], hex)
	-raw:                Performs a raw copy of the bytes instead of interpreting them`
)

func init() {
	flag.StringVar(&value, "value", "", valueUsage)
	flag.StringVar(&value, "v", "", valueUsage+shorthand)
	flag.StringVar(&sourceFilename, "from", "", sourceFilenameUsage)
	flag.StringVar(&sourceFilename, "f", "", sourceFilenameUsage+shorthand)
	flag.StringVar(&destinationFilename, "to", "", destinationFilenameUsage)
	flag.StringVar(&destinationFilename, "t", "", destinationFilenameUsage+shorthand)
	flag.StringVar(&sourceAttribute, "sa", "", sourceAttributeUsage)
	flag.StringVar(&destinationAttribute, "da", "", destinationAttributeUsage)
	flag.StringVar(&inputMode, "input", "", inputModeUsage)
	flag.StringVar(&inputMode, "in", "", inputModeUsage+shorthand)
	flag.StringVar(&inputMode, "i", "", inputModeUsage+shorthand)
	flag.StringVar(&outputMode, "output", "", outputModeUsage)
	flag.StringVar(&outputMode, "out", "", outputModeUsage+shorthand)
	flag.StringVar(&outputMode, "o", "", outputModeUsage+shorthand)
	flag.StringVar(&encoding, "encoding", "", encodingUsage)
	flag.StringVar(&encoding, "enc", "", encodingUsage+shorthand)
	flag.StringVar(&encoding, "e", "", encodingUsage+shorthand)
	flag.BoolVar(&raw, "raw", false, rawUsage)
}

func main() {
	flag.Parse()

	// Perform case insensitive flag matching for these values
	inputMode = strings.ToLower(inputMode)
	outputMode = strings.ToLower(outputMode)
	encoding = strings.ToLower(encoding)

	// Step 1: Grab the raw security descriptor bytes
	var (
		inputBytes  []byte
		outputBytes []byte
		err         error
	)

	switch {
	case value != "":
		if sourceFilename != "" {
			fmt.Println("Cannot specify both source filename and source value")
			fmt.Println(usage)
			os.Exit(1)
		}
		switch inputMode {
		case modeNTFS, modeSamba:
			// Autodetect encoding for these input modes
			inputBytes, err = base64.StdEncoding.DecodeString(value)
			if err != nil {
				inputBytes, err = hex.DecodeString(value)
				if err != nil {
					fmt.Println("Input value must be encoded in hexadecimal or base64")
					os.Exit(1)
				}
			}
		case modeSDDL:
			fmt.Println("SDDL input mode is not yet supported")
			os.Exit(1)
		default:
			fmt.Println("Invalid input mode")
			fmt.Println(usage)
			os.Exit(1)
		}
	case sourceFilename != "":
		if _, err := os.Stat(sourceFilename); err != nil {
			if os.IsNotExist(err) {
				log.Fatal(err)
			}
			log.Fatal("Unable to access source file: ", err)
		}
		switch inputMode {
		case modeNTFS:
			if sourceAttribute == "" {
				inputBytes, err = ntfs.ReadFileRawSD(sourceFilename)
			} else {
				inputBytes, err = ntfs.ReadFileAttribute(sourceFilename, sourceAttribute)
			}
			if err != nil {
				log.Fatal(err)
			}
		case modeSamba:
			if sourceAttribute == "" {
				inputBytes, err = samba.ReadFileRawSD(sourceFilename)
			} else {
				inputBytes, err = samba.ReadFileAttribute(sourceFilename, sourceAttribute)
			}
		case modeSDDL:
			fmt.Println("Invalid source mode while reading input from file attributes")
			fmt.Println(usage)
			os.Exit(1)
		default:
			fmt.Println("Invalid input mode")
			fmt.Println(usage)
			os.Exit(1)
		}
	default:
		fmt.Println(usage)
		os.Exit(1)
	}

	if raw && inputMode == outputMode && (inputMode == modeNTFS || inputMode == modeSamba) {
		outputBytes = inputBytes
	} else {
		var sd ntsecurity.SecurityDescriptor

		// Step 2: Unmarshal the input
		switch inputMode {
		case modeNTFS:
			err = sd.UnmarshalBinary(inputBytes)
			if err != nil {
				log.Fatal(err)
			}
		case modeSamba:
			err = (*samba.SambaSecDescXAttr)(&sd).UnmarshalBinary(inputBytes)
			if err != nil {
				log.Fatal(err)
			}
		case modeSDDL:
			log.Fatal("SDDL parsing has not been implemented yet")
		}

		// Step 4: Marshal the output
		switch outputMode {
		case modeSDDL:
			outputBytes = []byte(sd.SDDL())
		case modeNTFS:
			if outputBytes, err = sd.MarshalBinary(); err != nil {
				log.Fatal(err)
			}
		case modeSamba:
			if outputBytes, err = (*samba.SambaSecDescXAttr)(&sd).MarshalBinary(); err != nil {
				log.Fatal(err)
			}
		default:
			fmt.Println("Invalid output mode")
			fmt.Println(usage)
			os.Exit(1)
		}
	}

	// Step 5a: Write the output to the destination
	if destinationFilename != "" {
		if _, err = os.Stat(destinationFilename); err != nil {
			if os.IsNotExist(err) {
				log.Fatal(err)
			}
			log.Fatal("Unable to access destination file: ", err)
		}
		switch outputMode {
		case modeNTFS:
			if destinationAttribute == "" {
				err = ntfs.WriteFileRawSD(destinationFilename, outputBytes)
			} else {
				err = ntfs.WriteFileAttribute(destinationFilename, sourceAttribute, outputBytes)
			}
			if err != nil {
				log.Fatal(err)
			}
			os.Exit(0)
		case modeSamba:
			if destinationAttribute == "" {
				err = samba.WriteFileRawSD(destinationFilename, outputBytes)
			} else {
				err = samba.WriteFileAttribute(destinationFilename, sourceAttribute, outputBytes)
			}
			if err != nil {
				log.Fatal(err)
			}
			os.Exit(0)
		case modeSDDL:
			fmt.Println("Invalid destination mode while writing output to file attributes")
			fmt.Println(usage)
			os.Exit(1)
		default:
			fmt.Println("Writing to a destination filename is not yet supported.")
			os.Exit(1)
			// if err := samba.Write(*destinationFilename, outputBytes); err != nil {
			// 	log.Fatal(err)
			// }
		}
	}

	// Step 5b: Write the output to stdout
	if outputMode == modeSDDL {
		// Write the SDDL representation of the security descriptor to the screen
		fmt.Println(string(outputBytes))
		os.Exit(0)
	}

	switch encoding {
	case encBase64:
		fmt.Println(base64.StdEncoding.EncodeToString(outputBytes))
		os.Exit(0)
	case encHex:
		fmt.Println(hex.EncodeToString(outputBytes))
		os.Exit(0)
	case "":
		print(outputBytes)
		os.Exit(0)
	default:
		fmt.Println("Invalid encoding")
		fmt.Println(usage)
		os.Exit(1)
	}
}
