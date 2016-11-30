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

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"path"
	"strings"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/google/certificate-transparency-go/x509util"
)

var verbose = flag.Bool("verbose", false, "Verbose output")
var issuerCertFlag = flag.String("issuer", "", "Issuer certificate")
var privKeyFlag = flag.String("private_key", "", "Issuer private key file")
var privKeyPassword = flag.String("private_key_password", "", "Issuer private key password")
var pubKeyFlag = flag.String("public_key", "", "Replacement public key for certificate")
var ignore = flag.String("ignore", "", "Comma-separated list of x509 parsing error IDs to ignore")
var makePrecert = flag.Bool("make_precert", false, "Force re-created cert to be RFC6962 pre-cert")
var dumpDir = flag.String("dump_dir", "", "Directory to store re-signed/re-created certificates in")

func main() {
	flag.Parse()
	if *issuerCertFlag == "" {
		log.Fatal("Issuer certificate (--issuer) required")
	}
	if *privKeyFlag == "" {
		log.Fatal("Issuer private key (--private_key) required")
	}
	issuer, _, err := getCert(*issuerCertFlag, nil)
	if issuer == nil || err != nil {
		log.Fatalf("Failed to load issuer certificate %s: %v", *issuerCertFlag, err)
	}
	privKey, signAlgo, err := loadPrivateKey(*privKeyFlag, *privKeyPassword)
	if err != nil {
		log.Fatalf("Failed to load private key %s: %v", *privKeyFlag, err)
	}
	var pubKey crypto.PublicKey
	if *pubKeyFlag != "" {
		var err error
		pubKey, err = loadPublicKey(*pubKeyFlag)
		if err != nil {
			log.Fatalf("Failed to load public key: %v", err)
		}
	}
	ignoredIDs := x509.ErrorFilter(*ignore)

	for _, filename := range flag.Args() {
		cert, errs, err := getCert(filename, ignoredIDs)
		if cert == nil || err != nil {
			log.Printf("%s: could not parse: %v\n", filename, errs.Error())
			continue
		}
		if *pubKeyFlag == "" {
			// Use the public key in the certificate already,
			pubKey = cert.PublicKey
		}
		cert.SignatureAlgorithm = signAlgo
		if *makePrecert {
			// Add the CT poison extension.
			cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
				Id:       x509.OIDExtensionCTPoison,
				Critical: true,
				Value:    []byte{asn1.TagNull, 0x00},
			})
		}

		newCertData, err := x509.CreateCertificate(rand.Reader, cert, issuer, pubKey, privKey)
		if err != nil {
			log.Printf("%s: CreateCertificate() = nil,%v", filename, err)
			if *verbose {
				log.Print("Cert that failed as a template:")
				log.Print(x509util.CertificateToString(cert))
			}
		}
		if newCertData == nil {
			continue
		}
		newCert, newErrs := x509.ParseCertificateLax(newCertData)
		// Check that any parse errors for the re-created certificate are a subset of
		// the original set of parse errors.
		diffErrs := errsSubtract(newErrs, errs)
		if len(diffErrs.Errs) > 0 {
			log.Printf("%s: created certificate has new parse errors: %v", filename, diffErrs)
		}
		if *verbose && newCert != nil {
			log.Print(x509util.CertificateToString(newCert))
		}
		if *dumpDir != "" {
			filename := path.Join(*dumpDir, path.Base(filename))
			if err := ioutil.WriteFile(filename, newCertData, 0644); err != nil {
				log.Printf("%s: Failed to dump new cert data: %v", filename, err)
			}
		}
	}
}

func loadPrivateKey(filename, password string) (crypto.PrivateKey, x509.SignatureAlgorithm, error) {
	pemData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("failed to read private key PEM file: %v", err)
	}

	block, rest := pem.Decode([]byte(pemData))
	if len(rest) > 0 {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("extra data found after PEM decoding")
	}

	der := block.Bytes
	if password != "" {
		der, err = x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("failed to decrypt PEM block: %v", err)
		}
	}

	key, algo, err := parsePrivateKey(der)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("failed to parse private key: %v", err)
	}
	return key, algo, nil
}

func parsePrivateKey(key []byte) (crypto.PrivateKey, x509.SignatureAlgorithm, error) {
	if key, err := x509.ParsePKCS1PrivateKey(key); err == nil {
		return key, x509.SHA256WithRSA, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(key); err == nil {
		switch key := key.(type) {
		case *ecdsa.PrivateKey:
			return key, x509.ECDSAWithSHA256, nil
		case *rsa.PrivateKey:
			return key, x509.SHA256WithRSA, nil
		default:
			return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("unknown private key type: %T", key)
		}
	}
	if key, err := x509.ParseECPrivateKey(key); err == nil {
		return key, x509.ECDSAWithSHA256, nil
	}
	return nil, x509.UnknownSignatureAlgorithm, errors.New("could not parse private key")
}

func getCert(filename string, ignoredIDs []x509.ErrorID) (*x509.Certificate, x509.Errors, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, x509.Errors{}, fmt.Errorf("failed to read data: %v", err)
	}
	// Auto-detect PEM files.
	if strings.Contains(string(data), "BEGIN CERTIFICATE") {
		block, _ := pem.Decode([]byte(data))
		if block != nil && block.Type == "CERTIFICATE" {
			data = block.Bytes
		}
	}
	cert, errs := x509.ParseCertificateLax(data)
	return cert, errs, nil
}

func loadPublicKey(filename string) (crypto.PublicKey, error) {
	pemData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key PEM file: %v", err)
	}
	pubkey, _, _, err := ct.PublicKeyFromPEM(pemData)
	return pubkey, err
}

func errsSubtract(new, old x509.Errors) x509.Errors {
	var diff x509.Errors
outer:
	for _, newErr := range new.Errs {
		for _, oldErr := range old.Errs {
			if newErr.ID == oldErr.ID {
				continue outer
			}
		}
		diff.Errs = append(diff.Errs, newErr)
	}
	return diff
}
