// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package x509util

import (
	"testing"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

func TestOIDForStandardExtension(t *testing.T) {
	tests := []struct {
		oid  asn1.ObjectIdentifier
		want bool
	}{
		{
			oid:  asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6},
			want: false,
		},
		{
			oid:  x509.OIDExtensionSubjectAltName,
			want: true,
		},
	}
	for _, test := range tests {
		if got := OIDForStandardExtension(test.oid); got != test.want {
			t.Errorf("OIDForStandardExtension(%s)=%v, want %v", test.oid, got, test.want)
		}
	}
}
func TestOIDInExtensions(t *testing.T) {
	tests := []struct {
		oid          asn1.ObjectIdentifier
		exts         []pkix.Extension
		wantCount    int
		wantCritical bool
	}{
		{
			oid: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6},
			exts: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6}, Critical: false},
			},
			wantCount:    1,
			wantCritical: false,
		},
		{
			oid: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6},
			exts: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6}, Critical: false},
				{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6}, Critical: true},
			},
			wantCount:    2,
			wantCritical: true,
		},
		{
			oid: x509.OIDExtensionSubjectAltName,
			exts: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6}, Critical: false},
			},
			wantCount:    0,
			wantCritical: false,
		},
	}
	for _, test := range tests {
		gotCount, gotCritical := OIDInExtensions(test.oid, test.exts)
		if gotCount != test.wantCount || gotCritical != test.wantCritical {
			t.Errorf("OIDInExtensions(%s, %v)=%d,%v; want %d,%v", test.oid, test.exts, gotCount, gotCritical, test.wantCount, test.wantCritical)
		}
	}
}
