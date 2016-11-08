// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkix_test

import (
	"encoding/hex"
	"testing"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

func TestNamesEqual(t *testing.T) {
	var tests = []struct {
		desc string
		in   [2]string // hex-encoded
		want bool
	}{
		{
			desc: "identical",
			in: [2]string{
				("3054" + // SEQUENCE
					("310B" + // SET
						("3009" + // SEQUENCE
							("0603" + "550406") + // OID: 2.5.4.6
							("1302" + "5553"))) + // PrintableString "US"
					("311E" + // SET
						("301C" + // SEQUENCE
							("0603" + "55040A") + // OID: 2.5.4.10
							("1315" + "476F6F676C65205472757374205365727669636573"))) + // PrintableString "Google Trust Services"
					("3125" + // SET
						("3023" + // SEQUENCE
							("0603" + "550403") + // OID: 2.5.4.3
							("131C" + "476F6F676C6520496E7465726E657420417574686F72697479204733")))), // PrintableString "Google Internet Authority G3"
				("3054" + // SEQUENCE
					("310B" + // SET
						("3009" + // SEQUENCE
							("0603" + "550406") + // OID: 2.5.4.6
							("1302" + "5553"))) + // PrintableString "US"
					("311E" + // SET
						("301C" + // SEQUENCE
							("0603" + "55040A") + // OID: 2.5.4.10
							("1315" + "476F6F676C65205472757374205365727669636573"))) + // PrintableString "Google Trust Services"
					("3125" + // SET
						("3023" + // SEQUENCE
							("0603" + "550403") + // OID: 2.5.4.3
							("131C" + "476F6F676C6520496E7465726E657420417574686F72697479204733")))), // PrintableString "Google Internet Authority G3"
			},
			want: true,
		},
		{
			desc: "different-country",
			in: [2]string{
				("3054" + // SEQUENCE
					("310B" + // SET
						("3009" + // SEQUENCE
							("0603" + "550406") + // OID: 2.5.4.6
							("1302" + "554B"))) + // PrintableString "UK"
					("311E" + // SET
						("301C" + // SEQUENCE
							("0603" + "55040A") + // OID: 2.5.4.10
							("1315" + "476F6F676C65205472757374205365727669636573"))) + // PrintableString "Google Trust Services"
					("3125" + // SET
						("3023" + // SEQUENCE
							("0603" + "550403") + // OID: 2.5.4.3
							("131C" + "476F6F676C6520496E7465726E657420417574686F72697479204733")))), // PrintableString "Google Internet Authority G3"
				("3054" + // SEQUENCE
					("310B" + // SET
						("3009" + // SEQUENCE
							("0603" + "550406") + // OID: 2.5.4.6
							("1302" + "5553"))) + // PrintableString "US"
					("311E" + // SET
						("301C" + // SEQUENCE
							("0603" + "55040A") + // OID: 2.5.4.10
							("1315" + "476F6F676C65205472757374205365727669636573"))) + // PrintableString "Google Trust Services"
					("3125" + // SET
						("3023" + // SEQUENCE
							("0603" + "550403") + // OID: 2.5.4.3
							("131C" + "476F6F676C6520496E7465726E657420417574686F72697479204733")))), // PrintableString "Google Internet Authority G3"
			},
			want: false,
		},
		{
			desc: "different-string-type",
			in: [2]string{
				("3054" + // SEQUENCE
					("310B" + // SET
						("3009" + // SEQUENCE
							("0603" + "550406") + // OID: 2.5.4.6
							("0c02" + "5553"))) + // UTF8String "US"
					("311E" + // SET
						("301C" + // SEQUENCE
							("0603" + "55040A") + // OID: 2.5.4.10
							("1315" + "476F6F676C65205472757374205365727669636573"))) + // PrintableString "Google Trust Services"
					("3125" + // SET
						("3023" + // SEQUENCE
							("0603" + "550403") + // OID: 2.5.4.3
							("131C" + "476F6F676C6520496E7465726E657420417574686F72697479204733")))), // PrintableString "Google Internet Authority G3"
				("3054" + // SEQUENCE
					("310B" + // SET
						("3009" + // SEQUENCE
							("0603" + "550406") + // OID: 2.5.4.6
							("1302" + "5553"))) + // PrintableString "US"
					("311E" + // SET
						("301C" + // SEQUENCE
							("0603" + "55040A") + // OID: 2.5.4.10
							("1315" + "476F6F676C65205472757374205365727669636573"))) + // PrintableString "Google Trust Services"
					("3125" + // SET
						("3023" + // SEQUENCE
							("0603" + "550403") + // OID: 2.5.4.3
							("131C" + "476F6F676C6520496E7465726E657420417574686F72697479204733")))), // PrintableString "Google Internet Authority G3"
			},
			want: true,
		},
		{
			desc: "different-set-order",
			in: [2]string{
				("3054" + // SEQUENCE
					("311E" + // SET
						("301C" + // SEQUENCE
							("0603" + "55040A") + // OID: 2.5.4.10
							("1315" + "476F6F676C65205472757374205365727669636573"))) + // PrintableString "Google Trust Services"
					("310B" + // SET
						("3009" + // SEQUENCE
							("0603" + "550406") + // OID: 2.5.4.6
							("1302" + "5553"))) + // PrintableString "US"
					("3125" + // SET
						("3023" + // SEQUENCE
							("0603" + "550403") + // OID: 2.5.4.3
							("131C" + "476F6F676C6520496E7465726E657420417574686F72697479204733")))), // PrintableString "Google Internet Authority G3"
				("3054" + // SEQUENCE
					("310B" + // SET
						("3009" + // SEQUENCE
							("0603" + "550406") + // OID: 2.5.4.6
							("1302" + "5553"))) + // PrintableString "US"
					("311E" + // SET
						("301C" + // SEQUENCE
							("0603" + "55040A") + // OID: 2.5.4.10
							("1315" + "476F6F676C65205472757374205365727669636573"))) + // PrintableString "Google Trust Services"
					("3125" + // SET
						("3023" + // SEQUENCE
							("0603" + "550403") + // OID: 2.5.4.3
							("131C" + "476F6F676C6520496E7465726E657420417574686F72697479204733")))), // PrintableString "Google Internet Authority G3"
			},
			// RFC 5280 s7.1 "Two distinguished names DN1 and DN2 match if ... the matching RDNs appear in the same order in both DNs."
			want: false,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			var name [2]pkix.Name
			for i := 0; i < 2; i++ {
				data, err := hex.DecodeString(test.in[i])
				if err != nil {
					t.Fatalf("Failed to hex-decode hard-coded test data: %v", err)
				}
				var rdn pkix.RDNSequence
				if rest, err := asn1.Unmarshal(data, &rdn); err != nil {
					t.Fatalf("Failed to unmarshal hard-coded test data: %v", err)
				} else if len(rest) != 0 {
					t.Fatal("Trailing data in hard-coded test data")
				}
				name[i].FillFromRDNSequence(&rdn)
			}
			got := pkix.NamesEqual(&name[0], &name[1])
			if got != test.want {
				t.Errorf("NamesEqual('%+v', '%+v')=%v; want %v", name[0], name[1], got, test.want)
			}
		})
	}
}
