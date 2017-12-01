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

// certcheck is a utility to show and check the contents of certificates.
package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/ocsp"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
)

var (
	explicitIssuer = flag.String("issuer", "", "File containing issuer certificate")
	forcePost      = flag.Bool("post", false, "Whether to always POST the OCSP request")
	forceGet       = flag.Bool("get", false, "Whether to always GET the OCSP request")
)

func main() {
	flag.Parse()
	if *forcePost && *forceGet {
		glog.Exitf("Cannot --post and --get at the same time")
	}

	client := &http.Client{}
	var issuer *x509.Certificate
	if *explicitIssuer != "" {
		issuerData, err := x509util.ReadPossiblePEMFile(*explicitIssuer, "CERTIFICATE")
		if err != nil || len(issuerData) == 0 {
			glog.Exitf("failed to read --issuer cert: %v\n", err)
		}
		issuers, err := x509.ParseCertificates(issuerData[0])
		if err != nil {
			glog.Exitf("failed to parse --issuer cert: %v\n", err)
		}
		issuer = issuers[0]
		glog.Infof("Using explicit issuer %q", x509util.NameToString(issuer.Subject))
	}

	errored := false
	for _, filename := range flag.Args() {
		dataList, err := x509util.ReadPossiblePEMFile(filename, "CERTIFICATE")
		if err != nil {
			glog.Errorf("%s: Failed to read data: %v\n", filename, err)
			errored = true
			continue
		}
		for _, data := range dataList {
			certs, err := x509.ParseCertificates(data)
			if err != nil {
				glog.Errorf("%s: %v\n", filename, err.Error())
				errored = true
			}
			for _, cert := range certs {
				glog.Infof("Check cert %q", x509util.NameToString(cert.Subject))
				if err := ocspCheck(cert, issuer, client, *forcePost, *forceGet); err != nil {
					glog.Errorf("%s: %v\n", filename, err.Error())
					errored = true
				}
			}
		}
	}
	if errored {
		os.Exit(1)
	}
}

func ocspCheck(cert, issuer *x509.Certificate, client *http.Client, forcePost, forceGet bool) error {
	if len(cert.OCSPServer) == 0 {
		return errors.New("no OCSP URL in certificate")
	}
	ocspURL := cert.OCSPServer[0]

	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("certificate is expired (since %v)", cert.NotAfter)
	}
	if issuer == nil {
		var err error
		issuer, err = x509util.GetIssuer(cert, client)
		if err != nil {
			return err
		}
	}

	derReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return fmt.Errorf("failed to create OCSP request: %v", err)
	}
	ocspReq, err := ocsp.ParseRequest(derReq)
	if err != nil {
		return fmt.Errorf("failed to re-parse created OCSP request: %v", err)
	}
	glog.Infof("req:\n%s", x509util.OCSPRequestToString(ocspReq))

	usePost := len(derReq) >= 255
	if forcePost {
		usePost = true
	}
	if forceGet {
		usePost = false
	}

	var rsp *http.Response
	if usePost {
		glog.Infof("retrieving OCSP data from POST to %q", ocspURL)
		rsp, err = client.Post(ocspURL, "application/ocsp-request", bytes.NewReader(derReq))
	} else {
		glog.Infof("retrieving OCSP data from GET from %q", ocspURL)
		b64 := base64.StdEncoding.EncodeToString(derReq)
		rsp, err = client.Get(ocspURL + "/" + url.QueryEscape(b64))
	}
	if err != nil {
		return fmt.Errorf("failed to retrieve OCSP response: %v", err)
	}
	derRsp, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return fmt.Errorf("failed to read OCSP response from %q: %v", ocspURL, err)
	}
	rsp.Body.Close()

	ocspRsp, err := ocsp.ParseResponseForCert(derRsp, cert, issuer)
	if err != nil {
		return fmt.Errorf("failed to parse OCSP response from %q: %v", ocspURL, err)
	}
	glog.Infof("rsp:\n%s", x509util.OCSPResponseToString(ocspRsp))

	if ocspRsp.Status == ocsp.Revoked {
		glog.Errorf("%s: certificate with serial number %v revoked at %v\n", ocspURL, cert.SerialNumber, ocspRsp.RevokedAt)
		if ocspRsp.RevocationReason != ocsp.Unspecified {
			glog.Errorf("  revocation reason: %s\v", x509util.OCSPRevocationReasonToString(ocspRsp.RevocationReason))
		}
	}
	return nil
}
