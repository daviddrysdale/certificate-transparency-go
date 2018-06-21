// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"net"
	"net/url"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

const (
	// GeneralName tag values from RFC 5280, 4.2.1.6
	tagOtherName     = 0
	tagRFC822Name    = 1
	tagDNSName       = 2
	tagX400Address   = 3
	tagDirectoryName = 4
	tagEDIPartyName  = 5
	tagURI           = 6
	tagIPAddress     = 7
	tagRegisteredID  = 8
)

// OtherName describes a name related to a certificate which is not in one
// of the standard name formats. RFC 5280, 4.2.1.6:
// OtherName ::= SEQUENCE {
//      type-id    OBJECT IDENTIFIER,
//      value      [0] EXPLICIT ANY DEFINED BY type-id }
type OtherName struct {
	TypeID asn1.ObjectIdentifier
	Value  asn1.RawValue
}

// GeneralNames holds a collection of names related to a certificate.
type GeneralNames struct {
	DNSNames       []string
	EmailAddresses []string
	DirectoryNames []pkix.Name
	URIs           []*url.URL
	IPNets         []net.IPNet
	RegisteredIDs  []asn1.ObjectIdentifier
	OtherNames     []OtherName
}

// Len returns the total number of names in a GeneralNames object.
func (gn GeneralNames) Len() int {
	return (len(gn.DNSNames) + len(gn.EmailAddresses) + len(gn.DirectoryNames) +
		len(gn.URIs) + len(gn.IPNets) + len(gn.RegisteredIDs) + len(gn.OtherNames))
}

// Empty indicates whether a GeneralNames object is empty.
func (gn GeneralNames) Empty() bool {
	return gn.Len() == 0
}

func parseGeneralNames(value []byte, who string, gname *GeneralNames, errs *Errors) {
	parseGeneralNamesWithTag(value, who, asn1.ClassUniversal, asn1.TagSequence, gname, errs)
}

func parseGeneralNamesWithTag(value []byte, who string, wantClass, wantTag int, gname *GeneralNames, errs *Errors) {
	// RFC 5280, 4.2.1.6
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      rfc822Name                      [1]     IA5String,
	//      dNSName                         [2]     IA5String,
	//      x400Address                     [3]     ORAddress,
	//      directoryName                   [4]     Name,
	//      ediPartyName                    [5]     EDIPartyName,
	//      uniformResourceIdentifier       [6]     IA5String,
	//      iPAddress                       [7]     OCTET STRING,
	//      registeredID                    [8]     OBJECT IDENTIFIER }
	var seq asn1.RawValue
	var rest []byte
	if rest, err := asn1.Unmarshal(value, &seq); err != nil {
		errs.addIDFatal(ErrAsn1InvalidGeneralNames, who, err.Error())
		return
	} else if len(rest) != 0 {
		errs.addIDFatal(ErrAsn1TrailingGeneralNames, who)
		return
	}
	if !seq.IsCompound || seq.Tag != wantTag || seq.Class != wantClass {
		errs.addIDFatal(ErrInvalidGeneralNamesTag, seq.Tag, seq.Class, who)
		return
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		rest = parseGeneralName(rest, who, gname, false, errs)
		if errs.Fatal() {
			return
		}
	}
}

func parseGeneralName(data []byte, who string, gname *GeneralNames, withMask bool, errs *Errors) []byte {
	var v asn1.RawValue
	var rest []byte
	var err error
	rest, err = asn1.Unmarshal(data, &v)
	if err != nil {
		errs.addIDFatal(ErrAsn1InvalidGeneralName, who, err)
		return nil
	}
	switch v.Tag {
	case tagOtherName:
		if !v.IsCompound {
			errs.addIDFatal(ErrAsn1InvalidGeneralNameOtherNotCompound, who)
			return nil
		}
		var other OtherName
		v.FullBytes = append([]byte{}, v.FullBytes...)
		v.FullBytes[0] = asn1.TagSequence | 0x20
		_, err = asn1.Unmarshal(v.FullBytes, &other)
		if err != nil {
			errs.addIDFatal(ErrAsn1InvalidGeneralNameOther, who, err)
			return nil
		}
		gname.OtherNames = append(gname.OtherNames, other)
	case tagRFC822Name:
		gname.EmailAddresses = append(gname.EmailAddresses, string(v.Bytes))
	case tagDNSName:
		dns := string(v.Bytes)
		gname.DNSNames = append(gname.DNSNames, dns)
	case tagDirectoryName:
		var rdnSeq pkix.RDNSequence
		if _, err := asn1.Unmarshal(v.Bytes, &rdnSeq); err != nil {
			errs.addIDFatal(ErrAsn1InvalidGeneralNameDirectory, who, err)
			return nil
		}
		var dirName pkix.Name
		dirName.FillFromRDNSequence(&rdnSeq)
		gname.DirectoryNames = append(gname.DirectoryNames, dirName)
	case tagURI:
		uri, err := url.Parse(string(v.Bytes))
		if err != nil {
			errs.addIDFatal(ErrAsn1InvalidGeneralNameURI, who, string(v.Bytes), err)
			return nil
		}
		if len(uri.Host) > 0 {
			if _, ok := domainToReverseLabels(uri.Host); !ok {
				errs.addIDFatal(ErrInvalidGeneralNameURI, who, string(v.Bytes))
				return nil
			}
		}
		gname.URIs = append(gname.URIs, uri)
	case tagIPAddress:
		vlen := len(v.Bytes)
		if withMask {
			switch vlen {
			case (2 * net.IPv4len), (2 * net.IPv6len):
				ipNet := net.IPNet{IP: v.Bytes[0 : vlen/2], Mask: v.Bytes[vlen/2:]}
				gname.IPNets = append(gname.IPNets, ipNet)
			default:
				errs.AddID(ErrGeneralNameIPMaskLen, who, vlen)
			}
		} else {
			switch vlen {
			case net.IPv4len, net.IPv6len:
				ipNet := net.IPNet{IP: v.Bytes}
				gname.IPNets = append(gname.IPNets, ipNet)
			default:
				errs.AddID(ErrGeneralNameIPLen, who, vlen)
			}
		}
	case tagRegisteredID:
		var oid asn1.ObjectIdentifier
		v.FullBytes = append([]byte{}, v.FullBytes...)
		v.FullBytes[0] = asn1.TagOID
		_, err = asn1.Unmarshal(v.FullBytes, &oid)
		if err != nil {
			errs.addIDFatal(ErrAsn1InvalidGeneralNameOID, who, err)
			return nil
		}
		gname.RegisteredIDs = append(gname.RegisteredIDs, oid)
	default:
		errs.addIDFatal(ErrInvalidGeneralNameTag, v.Tag, who)
		return nil
	}
	return rest
}
