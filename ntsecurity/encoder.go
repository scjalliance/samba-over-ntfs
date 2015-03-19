package ntsecurity

import "io"

type Encoder struct {
	w io.Writer
}

func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

func (enc *Encoder) EncodeSecurityDescriptor(sd *SecurityDescriptor) {
	//var b [16]byte
	//enc.w.Write(unsafe.)
}
