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

type oidTest struct {
	oid      asn1.ObjectIdentifier
	std      bool
	exts     []pkix.Extension
	count    int
	critical bool
}

var oidTestData = []oidTest{
	{
		oid: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6},
		std: false,
		exts: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6},
				Critical: false,
			},
		},
		count:    1,
		critical: false,
	},
	{
		oid: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6},
		std: false,
		exts: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6},
				Critical: false,
			},
			{
				Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6},
				Critical: true,
			},
		},
		count:    2,
		critical: true,
	},
	{
		oid: x509.OIDExtensionSubjectAltName,
		std: true,
		exts: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6},
				Critical: false,
			},
		},
		count:    0,
		critical: false,
	},
}

func TestOIDs(t *testing.T) {
	for i, test := range oidTestData {
		std := OIDForStandardExtension(test.oid)
		if std != test.std {
			t.Errorf("#%d: Bad result for %s: %v (expected %v)", i, test.oid, std, test.std)
		}
		count, critical := OIDInExtensions(test.oid, test.exts)
		if count != test.count {
			t.Errorf("#%d: Bad result for oid %s count: %d (expected %d)", i, test.oid, count, test.count)
		}
		if critical != test.critical {
			t.Errorf("#%d: Bad result for oid %s critical: %v (expected %v)", i, test.oid, critical, test.critical)
		}
	}
}
