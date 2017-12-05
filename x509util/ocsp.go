// Copyright 2017 Google Inc. All Rights Reserved.
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
	"bytes"
	"crypto"
	"fmt"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/ocsp"
)

// HashAlgorithmToString generates a string for a hash algorithm.
func HashAlgorithmToString(h crypto.Hash) string {
	switch h {
	case crypto.SHA1:
		return "SHA1"
	case crypto.SHA256:
		return "SHA256"
	case crypto.SHA384:
		return "SHA384"
	case crypto.SHA512:
		return "SHA512"
	default:
		return fmt.Sprintf("Unknown hash %d", h)
	}
}

// OCSPRequestToString generates a string describing the given OCSP request.
// The output roughly resembles that from `openssl ocsp -text`.
func OCSPRequestToString(req *ocsp.Request) string {
	var result bytes.Buffer
	result.WriteString(fmt.Sprintf("OCSP Request Data:\n"))
	version := 0 // TODO(drysdale): get from request
	result.WriteString(fmt.Sprintf("    Version: %d (%#x)\n", version+1, version))
	result.WriteString(fmt.Sprintf("    Requestor List:\n"))

	result.WriteString(fmt.Sprintf("        Certificate ID:\n"))
	result.WriteString(fmt.Sprintf("          Hash Algorithm: %s\n", HashAlgorithmToString(req.HashAlgorithm)))
	result.WriteString(fmt.Sprintf("          Issuer Name Hash: %x\n", req.IssuerNameHash))
	result.WriteString(fmt.Sprintf("          Issuer Key Hash: %x\n", req.IssuerKeyHash))
	result.WriteString(fmt.Sprintf("          Serial Number: %d (%#[1]x)\n", req.SerialNumber))

	result.WriteString(fmt.Sprintf("    Request Extensions:\n"))

	return result.String()
}

// OCSPResponseToString generates a string describing the given OCSP response.
// The output roughly resembles that from `openssl ocsp -text`.
func OCSPResponseToString(rsp *ocsp.Response) string {
	var result bytes.Buffer
	result.WriteString(fmt.Sprintf("OCSP Response Data:\n"))
	rspStatus := ocsp.Success // TODO(drysdale): get from response
	result.WriteString(fmt.Sprintf("    OCSP Response Status: %s (%#x)\n", ocsp.ResponseStatus(rspStatus), rsp.Status))
	rspType := ocsp.OIDResponseTypePKIXOCSPBasic // TODO(drysdale): get from response
	result.WriteString(fmt.Sprintf("    Response Type: %s\n", ocspResponseTypeToString(rspType)))
	version := 0 // TODO(drysdale): get from response
	result.WriteString(fmt.Sprintf("    Version: %d (%#x)\n", version+1, version))
	if len(rsp.ResponderKeyHash) > 0 {
		result.WriteString(fmt.Sprintf("    Responder Id: %x\n", rsp.ResponderKeyHash))
	} else {
		// TODO(drysdale): parse the DER of the name and display it
		result.WriteString(fmt.Sprintf("    Responder Id: %x\n", rsp.RawResponderName))
	}
	result.WriteString(fmt.Sprintf("    Produced At: %v\n", rsp.ProducedAt))
	result.WriteString(fmt.Sprintf("    Responses:\n"))
	// TODO(drysdale): emit certificate info here when available
	result.WriteString(fmt.Sprintf("    Cert Status: %s\n", ocspStatusToString(rsp.Status)))
	if rsp.Status == ocsp.Revoked {
		result.WriteString(fmt.Sprintf("      Revocation Reason: %s\n", OCSPRevocationReasonToString(rsp.RevocationReason)))
	}
	result.WriteString(fmt.Sprintf("    This Update: %v\n", rsp.ThisUpdate))
	result.WriteString(fmt.Sprintf("    Next Update: %v\n", rsp.NextUpdate))
	result.WriteString(fmt.Sprintf("    Signature Algorithm: %v\n", rsp.SignatureAlgorithm))
	appendHexData(&result, rsp.Signature, 18, "         ")
	result.WriteString("\n")

	return result.String()
}

func ocspResponseTypeToString(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(ocsp.OIDResponseTypePKIXOCSPBasic):
		return "ocspResponseBasic"
	}
	return fmt.Sprintf("%v", oid)
}

func ocspStatusToString(s int) string {
	switch s {
	case ocsp.Good:
		return "Good"
	case ocsp.Revoked:
		return "Revoked"
	case ocsp.Unknown:
		return "Unknown"
	case ocsp.ServerFailed:
		return "ServerFailed"
	default:
		return fmt.Sprintf("unrecognized status (%d)", s)
	}
}

// OCSPRevocationReasonToString generates a string describing a revocation reason.
func OCSPRevocationReasonToString(r int) string {
	switch r {
	case ocsp.Unspecified:
		return "Unspecified"
	case ocsp.KeyCompromise:
		return "KeyCompromise"
	case ocsp.CACompromise:
		return "CACompromise"
	case ocsp.AffiliationChanged:
		return "AffiliationChanged"
	case ocsp.Superseded:
		return "Superseded"
	case ocsp.CessationOfOperation:
		return "CessationOfOperation"
	case ocsp.CertificateHold:
		return "CertificateHold"
	case ocsp.RemoveFromCRL:
		return "RemoveFromCRL"
	case ocsp.PrivilegeWithdrawn:
		return "PrivilegeWithdrawn"
	case ocsp.AACompromise:
		return "AACompromise"
	default:
		return fmt.Sprintf("unrecognized reason (%d)", r)
	}
}
