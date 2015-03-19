package samba

import (
	"io"

	"go.scj.io/samba-over-ntfs/ntsecurity"
)

type Encoder struct {
	w io.Writer
}

func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

func (enc *Encoder) EncodeXAttr(sd *ntsecurity.SecurityDescriptor) {
	//enc.w.Write()
}
