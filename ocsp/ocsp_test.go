// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.7

package ocsp

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"encoding/hex"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

func TestResponseStatusString(t *testing.T) {
	var tests = []struct {
		in   ResponseStatus
		want string
	}{
		{in: Success, want: "success"},
		{in: Malformed, want: "malformed"},
		{in: InternalError, want: "internal error"},
		{in: TryLater, want: "try later"},
		{in: SignatureRequired, want: "signature required"},
		{in: Unauthorized, want: "unauthorized"},
		{in: ResponseStatus(99), want: "unknown OCSP status: 99"},
	}
	for _, test := range tests {
		got := test.in.String()
		if got != test.want {
			t.Errorf("ResponseStatus(%d).String()=%q, want %q", test.in, got, test.want)
		}
	}
}

func TestOCSPDecode(t *testing.T) {
	responseBytes, _ := hex.DecodeString(ocspResponseHex)
	resp, err := ParseResponse(responseBytes, nil)
	if err != nil {
		t.Fatal(err)
	}

	responderCert, _ := hex.DecodeString(startComResponderCertHex)
	responder, err := x509.ParseCertificate(responderCert)
	if err != nil {
		t.Fatal(err)
	}

	expected := Response{
		Status:           Good,
		SerialNumber:     big.NewInt(0x1d0fa),
		RevocationReason: Unspecified,
		ThisUpdate:       time.Date(2010, 7, 7, 15, 1, 5, 0, time.UTC),
		NextUpdate:       time.Date(2010, 7, 7, 18, 35, 17, 0, time.UTC),
		RawResponderName: responder.RawSubject,
	}

	if !reflect.DeepEqual(resp.ThisUpdate, expected.ThisUpdate) {
		t.Errorf("resp.ThisUpdate: got %v, want %v", resp.ThisUpdate, expected.ThisUpdate)
	}

	if !reflect.DeepEqual(resp.NextUpdate, expected.NextUpdate) {
		t.Errorf("resp.NextUpdate: got %v, want %v", resp.NextUpdate, expected.NextUpdate)
	}

	if resp.Status != expected.Status {
		t.Errorf("resp.Status: got %d, want %d", resp.Status, expected.Status)
	}

	if resp.SerialNumber.Cmp(expected.SerialNumber) != 0 {
		t.Errorf("resp.SerialNumber: got %x, want %x", resp.SerialNumber, expected.SerialNumber)
	}

	if resp.RevocationReason != expected.RevocationReason {
		t.Errorf("resp.RevocationReason: got %d, want %d", resp.RevocationReason, expected.RevocationReason)
	}

	if !bytes.Equal(resp.RawResponderName, expected.RawResponderName) {
		t.Errorf("resp.RawResponderName: got %x, want %x", resp.RawResponderName, expected.RawResponderName)
	}

	if !bytes.Equal(resp.ResponderKeyHash, expected.ResponderKeyHash) {
		t.Errorf("resp.ResponderKeyHash: got %x, want %x", resp.ResponderKeyHash, expected.ResponderKeyHash)
	}
}

func TestOCSPDecodeWithoutCert(t *testing.T) {
	responseBytes, _ := hex.DecodeString(ocspResponseWithoutCertHex)
	_, err := ParseResponse(responseBytes, nil)
	if err != nil {
		t.Error(err)
	}
}

func TestOCSPDecodeWithExtensions(t *testing.T) {
	responseBytes, _ := hex.DecodeString(ocspResponseWithCriticalExtensionHex)
	_, err := ParseResponse(responseBytes, nil)
	if err == nil {
		t.Error(err)
	}

	responseBytes, _ = hex.DecodeString(ocspResponseWithExtensionHex)
	response, err := ParseResponse(responseBytes, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(response.Extensions) != 1 {
		t.Errorf("len(response.Extensions): got %v, want %v", len(response.Extensions), 1)
	}

	extensionBytes := response.Extensions[0].Value
	expectedBytes, _ := hex.DecodeString(ocspExtensionValueHex)
	if !bytes.Equal(extensionBytes, expectedBytes) {
		t.Errorf("response.Extensions[0]: got %x, want %x", extensionBytes, expectedBytes)
	}
}

func TestOCSPSignature(t *testing.T) {
	issuerCert, _ := hex.DecodeString(startComHex)
	issuer, err := x509.ParseCertificate(issuerCert)
	if err != nil {
		t.Fatal(err)
	}

	response, _ := hex.DecodeString(ocspResponseHex)
	if _, err := ParseResponse(response, issuer); err != nil {
		t.Error(err)
	}
}

func TestParseRequest(t *testing.T) {
	var tests = []struct {
		desc    string
		in      string // as hex
		wantErr string
	}{
		{
			desc: "valid request",
			in: ("3051" + // OCSPRequest SEQUENCE
				("304f" + // TBSRequest SEQUENCE
					("304d" + // SEQUENCE OF Request
						("304b" + // Request SEQUENCE
							("3049" + // CertID SEQUENCE
								("3009" + // hashAlgorithm AlgorithmIdentifier SEQUENCE
									("0605" + "2b0e03021a") + // OID:  1.3.14.3.2.26 (sha1)
									"0500") + // NULL
								("0414" + // issuerNameHash OCTET STRING
									"c0fe0278fc99188891b3f212e9c7e1b21ab7bfc0") +
								("0414" + // issuerKeyHash OCTET STRING
									"0dfc1df0a9e0f01ce7f2b213177e6f8d157cd4f6") +
								("0210" + // CertificateSerialNumber INTEGER
									"017f77deb3bcbb235d44ccc7dba62e72")))))),
		},
		{
			desc: "valid multi-cert request",
			in: ("3081a0" + // OCSPRequest SEQUENCE
				("30819d" + // TBSRequest SEQUENCE
					("30819a" + // SEQUENCE OF Request
						("304b" + // Request SEQUENCE
							("3049" + // CertID SEQUENCE
								("3009" + // hashAlgorithm AlgorithmIdentifier SEQUENCE
									("0605" + "2b0e03021a") + // OID:  1.3.14.3.2.26 (sha1)
									"0500") + // NULL
								("0414" + // issuerNameHash OCTET STRING
									"c0fe0278fc99188891b3f212e9c7e1b21ab7bfc0") +
								("0414" + // issuerKeyHash OCTET STRING
									"0dfc1df0a9e0f01ce7f2b213177e6f8d157cd4f6") +
								("0210" + // CertificateSerialNumber INTEGER
									"017f77deb3bcbb235d44ccc7dba62e72"))) +
						("304b" + // Request SEQUENCE
							("3049" + // CertID SEQUENCE
								("3009" + // hashAlgorithm AlgorithmIdentifier SEQUENCE
									("0605" + "2b0e03021a") + // OID: 1.3.14.3.2.26 (sha1)
									"0500") + // NULL
								("0414" + // issuerNameHash OCTET STRING
									"c0fe0278fc99188891b3f212e9c7e1b21ab7bfc6") +
								("0414" + // issuerKeyHash OCTET STRING
									"0dfc1df0a9e0f01ce7f2b213177e6f8d157cd4f0") +
								("0210" + // CertificateSerialNumber INTEGER
									"017f77deb3bcbb235d44ccc7dba62e73")))))),
		},
		{
			desc: "trailing data",
			in: ("3051" + // OCSPRequest SEQUENCE
				("304f" + // TBSRequest SEQUENCE
					("304d" + // SEQUENCE OF Request
						("304b" + // Request SEQUENCE
							("3049" + // CertID SEQUENCE
								("3009" + // hashAlgorithm AlgorithmIdentifier SEQUENCE
									("0605" + "2b0e03021a") + // OID:  1.3.14.3.2.26 (sha1)
									"0500") + // NULL
								("0414" + // issuerNameHash OCTET STRING
									"c0fe0278fc99188891b3f212e9c7e1b21ab7bfc0") +
								("0414" + // issuerKeyHash OCTET STRING
									"0dfc1df0a9e0f01ce7f2b213177e6f8d157cd4f6") +
								("0210" + // CertificateSerialNumber INTEGER
									"017f77deb3bcbb235d44ccc7dba62e72"))))) +
				"ff"),
			wantErr: "trailing data",
		},
		{
			desc: "unknown hash OID",
			in: ("3051" + // OCSPRequest SEQUENCE
				("304f" + // TBSRequest SEQUENCE
					("304d" + // SEQUENCE OF Request
						("304b" + // Request SEQUENCE
							("3049" + // CertID SEQUENCE
								("3009" + // hashAlgorithm AlgorithmIdentifier SEQUENCE
									("0605" + "2b0e030201") + // OID:  1.3.14.3.2.1
									"0500") + // NULL
								("0414" + // issuerNameHash OCTET STRING
									"c0fe0278fc99188891b3f212e9c7e1b21ab7bfc0") +
								("0414" + // issuerKeyHash OCTET STRING
									"0dfc1df0a9e0f01ce7f2b213177e6f8d157cd4f6") +
								("0210" + // CertificateSerialNumber INTEGER
									"017f77deb3bcbb235d44ccc7dba62e72")))))),
			wantErr: "unknown hash function",
		},
		{
			desc:    "bogus data",
			in:      "000000",
			wantErr: "asn1: structure error",
		},
	}
	for _, test := range tests {
		data, _ := hex.DecodeString(test.in)
		got, err := ParseRequest(data)
		if err != nil {
			if test.wantErr == "" {
				t.Errorf("ParseRequest(%s)=nil,%v; want _,nil", test.desc, err)
			} else if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("ParseRequest(%s)=nil,%v; want _,err containing %q", test.desc, err, test.wantErr)
			}
			continue
		}
		if test.wantErr != "" {
			t.Errorf("ParseRequest(%s)=%+v,nil; want nil, err containing %q", test.desc, got, test.wantErr)
		}

	}
}

func TestOCSPRequest(t *testing.T) {
	leafCert, _ := hex.DecodeString(leafCertHex)
	cert, err := x509.ParseCertificate(leafCert)
	if err != nil {
		t.Fatal(err)
	}

	issuerCert, _ := hex.DecodeString(issuerCertHex)
	issuer, err := x509.ParseCertificate(issuerCert)
	if err != nil {
		t.Fatal(err)
	}

	request, err := CreateRequest(cert, issuer, nil)
	if err != nil {
		t.Fatal(err)
	}

	expectedBytes, _ := hex.DecodeString(ocspRequestHex)
	if !bytes.Equal(request, expectedBytes) {
		t.Errorf("request: got %x, wanted %x", request, expectedBytes)
	}

	decodedRequest, err := ParseRequest(expectedBytes)
	if err != nil {
		t.Fatal(err)
	}

	if decodedRequest.HashAlgorithm != crypto.SHA1 {
		t.Errorf("request.HashAlgorithm: got %v, want %v", decodedRequest.HashAlgorithm, crypto.SHA1)
	}

	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo)
	if err != nil {
		t.Fatal(err)
	}

	h := sha1.New()
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	issuerKeyHash := h.Sum(nil)

	h.Reset()
	h.Write(issuer.RawSubject)
	issuerNameHash := h.Sum(nil)

	if got := decodedRequest.IssuerKeyHash; !bytes.Equal(got, issuerKeyHash) {
		t.Errorf("request.IssuerKeyHash: got %x, want %x", got, issuerKeyHash)
	}

	if got := decodedRequest.IssuerNameHash; !bytes.Equal(got, issuerNameHash) {
		t.Errorf("request.IssuerKeyHash: got %x, want %x", got, issuerNameHash)
	}

	if got := decodedRequest.SerialNumber; got.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("request.SerialNumber: got %x, want %x", got, cert.SerialNumber)
	}

	marshaledRequest, err := decodedRequest.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(expectedBytes, marshaledRequest) != 0 {
		t.Errorf(
			"Marshaled request doesn't match expected: wanted %x, got %x",
			expectedBytes,
			marshaledRequest,
		)
	}
}

func TestParseResponse(t *testing.T) {
	var tests = []struct {
		desc    string
		in      string // as hex
		want    Response
		wantErr string
	}{
		{
			desc: "valid response", // copy of ocspResponseWithoutCertHex below
			in: ("308206bc" + // OCSPResponse SEQUENCE
				"0a0100" + // responseStatus ENUMERATED = successful(0)
				("a08206b5" + // responseBytes [0] EXPLICIT
					("308206b1" + // ResponseBytes SEQUENCE
						"0609" + "2b0601050507300101" + // responseType OID = 1.3.6.1.5.5.7.48.1.1 = Basic Response
						("048206a2" + // response OCTET STRING
							("3082069e" + // BasicOCSPResponse SEQUENCE
								("3081c9" + // tbsResponseData ResponseData SEQUENCE
									("a14e" + // responderID byName [1] Name context-specific, constructed
										("304c" +
											("310b" +
												("3009" +
													"0603" + "550406" +
													"1302" + "494c")) +
											("3116" +
												("3014" +
													"0603" + "55040a" +
													"130d" + "5374617274436f6d204c74642e")) +
											("3125" +
												("3023" +
													"0603" + "550403" +
													"131c" + "5374617274436f6d20436c61" +
													"73732031204f435350205369676e6572")))) +
									("180f" + // producedAt GeneralizedTime
										"32303130303730373137333531375a") +
									("3066" + // responses SEQUENCE OF
										("3064" + // SingleResponse SEQUENCE
											("303c" + // CertID SEQUENCE
												("3009" + // hashAlgorithm AlgorithmIdentifier SEQUENCE
													"0605" + "2b0e03021a" + // OID: 1.3.14.3.2.26 (sha1)
													"0500") + // NULL
												("0414" + // issuerNameHash OCTET STRING
													"6568874f40750f016a3475625e1f5c93e5a26d58") +
												("0414" + // issuerKeyHash OCTET STRING
													"eb4234d098b0ab9ff41b6b08f7cc642eef0e2c45") +
												("0203" + "01d0fa")) + // CertificateSerialNumber INTEGER
											"8000" + // certStatus CHOICE = [0] good
											("180f" + // thisUpdate GeneralizedTime
												"32303130303730373135303130355a") +
											("a011" + // nextUpdate EXPLICIT [0]
												("180f" + // GeneralizedTime
													"32303130303730373138333531375a"))))) +
								("300d" + // signatureAlgorithm
									"0609" + "2a864886f70d010105" + // OID: 1.2.840.113549.1.1.5 sha1-with-rsa-signature
									"0500") + // NULL
								("03820101" + // signature BIT STRING
									"00ab557ff070d1d7cebbb5f0ec91a15c" +
									"3fed22eb2e1b8244f1b84545f013a4fb" +
									"46214c5e3fbfbebb8a56acc2b9db19f6" +
									"8fd3c3201046b3824d5ba689f9986432" +
									"8710cb467195eb37d84f539e49f85931" +
									"6b32964dc3e47e36814ce94d6c56dd02" +
									"733b1d0802f7ff4eebdbbd2927dcf580" +
									"f16cbc290f91e81b53cb365e7223f1d6" +
									"e20a88ea064104875e0145672b20fc14" +
									"829d51ca122f5f5d77d3ad6c83889c55" +
									"c7dc43680ba2fe3cef8b05dbcabdc0d3" +
									"e09aaf9725597f8c858c2fa38c0d6aed" +
									"2e6318194420dd1a1137445d13e1c97a" +
									"b4789617a4e08925f46f867b72e3a4dc" +
									"1f08cb870b2b0717f7207faa0ac512e6" +
									"28a029aba7457ae63dcf3281e2162d93" +
									"49") +
								("a08204ba" + // cert [0] EXPLICIT
									("308204b6" + // SEQUENCE OF
										("308204b2" + // Certificate
											("308203" +
												"9aa003020102020101300d06092a8648" +
												"86f70d010105050030818c310b300906" +
												"035504061302494c3116301406035504" +
												"0a130d5374617274436f6d204c74642e" +
												"312b3029060355040b13225365637572" +
												"65204469676974616c20436572746966" +
												"6963617465205369676e696e67313830" +
												"360603550403132f5374617274436f6d" +
												"20436c6173732031205072696d617279" +
												"20496e7465726d656469617465205365" +
												"72766572204341301e170d3037313032" +
												"353030323330365a170d313231303233" +
												"3030323330365a304c310b3009060355" +
												"04061302494c31163014060355040a13" +
												"0d5374617274436f6d204c74642e3125" +
												"30230603550403131c5374617274436f" +
												"6d20436c6173732031204f4353502053" +
												"69676e657230820122300d06092a8648" +
												"86f70d01010105000382010f00308201" +
												"0a0282010100b9561b4c453187171780" +
												"84e96e178df2255e18ed8d8ecc7c2b7b" +
												"51a6c1c2e6bf0aa3603066f132fe10ae" +
												"97b50e99fa24b83fc53dd2777496387d" +
												"14e1c3a9b6a4933e2ac12413d085570a" +
												"95b8147414a0bc007c7bcf222446ef7f" +
												"1a156d7ea1c577fc5f0facdfd42eb0f5" +
												"974990cb2f5cefebceef4d1bdc7ae5c1" +
												"075c5a99a93171f2b0845b4ff0864e97" +
												"3fcfe32f9d7511ff87a3e943410c90a4" +
												"493a306b6944359340a9ca96f02b66ce" +
												"67f028df2980a6aaee8d5d5d452b8b0e" +
												"b93f923cc1e23fcccbdbe7ffcb114d08" +
												"fa7a6a3c404f825d1a0e715935cf623a" +
												"8c7b59670014ed0622f6089a9447a7a1" +
												"9010f7fe58f84129a2765ea367824d1c" +
												"3bb2fda308530203010001a382015c30" +
												"820158300c0603551d130101ff040230" +
												"00300b0603551d0f0404030203a8301e" +
												"0603551d250417301506082b06010505" +
												"07030906092b0601050507300105301d" +
												"0603551d0e0416041445e0a36695414c" +
												"5dd449bc00e33cdcdbd2343e173081a8" +
												"0603551d230481a030819d8014eb4234" +
												"d098b0ab9ff41b6b08f7cc642eef0e2c" +
												"45a18181a47f307d310b300906035504" +
												"061302494c31163014060355040a130d" +
												"5374617274436f6d204c74642e312b30" +
												"29060355040b13225365637572652044" +
												"69676974616c20436572746966696361" +
												"7465205369676e696e67312930270603" +
												"55040313205374617274436f6d204365" +
												"7274696669636174696f6e2041757468" +
												"6f7269747982010a30230603551d1204" +
												"1c301a8618687474703a2f2f7777772e" +
												"737461727473736c2e636f6d2f302c06" +
												"096086480186f842010d041f161d5374" +
												"617274436f6d205265766f636174696f" +
												"6e20417574686f72697479300d06092a" +
												"864886f70d0101050500038201010018" +
												"2d22158f0fc0291324fa8574c49bb8ff" +
												"2835085adcbf7b7fc4191c397ab69513" +
												"28253fffe1e5ec2a7da0d50fca1a404e" +
												"6968481366939e666c0a6209073eca57" +
												"973e2fefa9ed1718e8176f1d85527ff5" +
												"22c08db702e3b2b180f1cbff05d98128" +
												"252cf0f450f7dd2772f4188047f19dc8" +
												"5317366f94bc52d60f453a550af58e30" +
												"8aaab00ced33040b62bf37f5b1ab2a4f" +
												"7f0f80f763bf4d707bc8841d7ad9385e" +
												"e2a4244469260b6f2bf085977af90747" +
												"96048ecc2f9d48a1d24ce16e41a99415" +
												"68fec5b42771e118f16c106a54ccc339" +
												"a4b02166445a167902e75e6d8620b082" +
												"5dcd18a069b90fd851d10fa8effd409d" +
												"eec02860d26d8d833f304b10669b42"))))))))),
			want: Response{
				Status:             Good,
				SerialNumber:       big.NewInt(119034),
				ProducedAt:         time.Date(2010, 7, 7, 17, 35, 17, 00, time.UTC),
				ThisUpdate:         time.Date(2010, 7, 7, 15, 1, 5, 00, time.UTC),
				NextUpdate:         time.Date(2010, 7, 7, 18, 35, 17, 00, time.UTC),
				SignatureAlgorithm: x509.SHA1WithRSA,
				IssuerHash:         crypto.SHA1,
			},
		},
		{
			desc: "revoked-cert", // For https://revoked.badssl.com
			in: ("308201e6" + // OCSPResponse SEQUENCE
				"0a0100" + // responseStatus ENUMERATED = successful(0)
				("a08201df" + // responseBytes [0] EXPLICIT
					("308201db" + // ResponseBytes SEQUENCE
						"0609" + "2b0601050507300101" + // responseType OID = 1.3.6.1.5.5.7.48.1.1 = Basic Response
						("048201cc" + // response OCTET STRING
							("308201c8" + // BasicOCSPResponse SEQUENCE
								("3081b1" + // tbsResponseData ResponseData SEQUENCE
									("a216" + // responderID byKey [2]
										("0414" + // KeyHash OCTETSTRING
											"0f80611c823161d52f28e78d4638b42ce1c6d9e2")) +
									("180f" + // producedAt GeneralizedTime
										"32303137313231393036353035325a") +
									("308185" + // SEQUENCE OF SingleResponse
										("308182" + // SingleResponse SEQUENCE
											("3049" + // CertID SEQUENCE
												("3009" + // hashAlgorithm AlgorithmIdentifier SEQUENCE
													"0605" + "2b0e03021a" + // OID: 1.3.14.3.2.26 (sha1)
													"0500") + // NULL
												("0414" + // issuerNameHash OCTET STRING
													"105fa67a80089db5279f35ce830b43889ea3c70d") +
												("0414" + // issuerKeyHash OCTET STRING
													"0f80611c823161d52f28e78d4638b42ce1c6d9e2") +
												("0210" + // certificateSerialNumber INTEGER
													"01af1efbdd5eae0952320b24fe6b5568")) +
											("a111" + // certStatus CHOICE = [1] revoked SEQUENCE
												("180f" + // revocationTime GeneralizedTime
													"32303136303930323231323834385a")) +
											("180f" + //  thisUpdate GeneralizedTime
												"32303137313231393036353035325a") +
											("a011" + // nextUpdate EXPLICIT[0]
												("180f" + // GeneralizedTime
													"32303137313232363036303535325a")))) +
									("300d" +
										"0609" + "2a864886f70d01010b" + // OID: 1.2.840.113549.1.1.11 sha256-with-rsa-signature
										"0500") + // NULL
									("03820101" + // signature BIT STRING
										"006c606b22a409123831ef30fc07e9a7" +
										"f70181b54cf01f743cc32c4da7dbf186" +
										"f22bae20dc721b20c869d9efb90e13c8" +
										"f7ab4fac4e70585626d9ea7689116fdc" +
										"15aba4e1b41a8eda2149db41b5e29f77" +
										"0d40006ed1eb7016385dca56c1acb355" +
										"b175031e846e6919002c1cf5177f285e" +
										"3f594c0a6b4c0cdce3fa739db89306cf" +
										"0255e6fbb24b86e5fa173d81af42e124" +
										"fd4efb92cfc4be09414a3e06dcfc98ea" +
										"9951c9e84d8ada1a995c7fb1c9b39237" +
										"2d8df14069aecce4845bd0760827e7de" +
										"06d7024bb9a6552a30506cc89e404322" +
										"c2fc05b0b42f28f975f44ca0da8c90e4" +
										"79f4ead03f90e8c7471a3130a82733b0" +
										"cb47c33a082e16f4a1503f66a3e7a59f" +
										"42"))))))),
			want: Response{
				Status:             Revoked,
				SerialNumber:       new(big.Int).SetBytes(fromHex("01af1efbdd5eae0952320b24fe6b5568")),
				ProducedAt:         time.Date(2017, 12, 19, 6, 50, 52, 00, time.UTC),
				ThisUpdate:         time.Date(2017, 12, 19, 6, 50, 52, 00, time.UTC),
				NextUpdate:         time.Date(2017, 12, 26, 6, 05, 52, 00, time.UTC),
				SignatureAlgorithm: x509.SHA256WithRSA,
				IssuerHash:         crypto.SHA1,
			},
		},
		{
			desc: "trailing data",
			in: ("308201e6" + // OCSPResponse SEQUENCE
				"0a0100" + // responseStatus ENUMERATED = successful(0)
				("a08201df" + // responseBytes [0] EXPLICIT
					("308201db" + // ResponseBytes SEQUENCE
						"0609" + "2b0601050507300101" + // responseType OID = 1.3.6.1.5.5.7.48.1.1 = Basic Response
						("048201cc" + // response OCTET STRING
							("308201c8" + // BasicOCSPResponse SEQUENCE
								("3081b1" + // tbsResponseData ResponseData SEQUENCE
									("a216" + // responderID byKey [2]
										("0414" + // KeyHash OCTETSTRING
											"0f80611c823161d52f28e78d4638b42ce1c6d9e2")) +
									("180f" + // producedAt GeneralizedTime
										"32303137313231393036353035325a") +
									("308185" + // SEQUENCE OF SingleResponse
										("308182" + // SingleResponse SEQUENCE
											("3049" + // CertID SEQUENCE
												("3009" + // hashAlgorithm AlgorithmIdentifier SEQUENCE
													"0605" + "2b0e03021a" + // OID: 1.3.14.3.2.26 (sha1)
													"0500") + // NULL
												("0414" + // issuerNameHash OCTET STRING
													"105fa67a80089db5279f35ce830b43889ea3c70d") +
												("0414" + // issuerKeyHash OCTET STRING
													"0f80611c823161d52f28e78d4638b42ce1c6d9e2") +
												("0210" + // certificateSerialNumber INTEGER
													"01af1efbdd5eae0952320b24fe6b5568")) +
											("a111" + // certStatus CHOICE = [1] revoked SEQUENCE
												("180f" + // revocationTime GeneralizedTime
													"32303136303930323231323834385a")) +
											("180f" + //  thisUpdate GeneralizedTime
												"32303137313231393036353035325a") +
											("a011" + // nextUpdate EXPLICIT[0]
												("180f" + // GeneralizedTime
													"32303137313232363036303535325a")))) +
									("300d" +
										"0609" + "2a864886f70d01010b" + // OID: 1.2.840.113549.1.1.11 sha256-with-rsa-signature
										"0500") + // NULL
									("03820101" + // signature BIT STRING
										"006c606b22a409123831ef30fc07e9a7" +
										"f70181b54cf01f743cc32c4da7dbf186" +
										"f22bae20dc721b20c869d9efb90e13c8" +
										"f7ab4fac4e70585626d9ea7689116fdc" +
										"15aba4e1b41a8eda2149db41b5e29f77" +
										"0d40006ed1eb7016385dca56c1acb355" +
										"b175031e846e6919002c1cf5177f285e" +
										"3f594c0a6b4c0cdce3fa739db89306cf" +
										"0255e6fbb24b86e5fa173d81af42e124" +
										"fd4efb92cfc4be09414a3e06dcfc98ea" +
										"9951c9e84d8ada1a995c7fb1c9b39237" +
										"2d8df14069aecce4845bd0760827e7de" +
										"06d7024bb9a6552a30506cc89e404322" +
										"c2fc05b0b42f28f975f44ca0da8c90e4" +
										"79f4ead03f90e8c7471a3130a82733b0" +
										"cb47c33a082e16f4a1503f66a3e7a59f" +
										"42")))))) + "ff"),
			wantErr: "trailing data",
		},
		{
			desc: "invalid response type",
			in: ("308201e6" + // OCSPResponse SEQUENCE
				"0a0100" + // responseStatus ENUMERATED = successful(0)
				("a08201df" + // responseBytes [0] EXPLICIT
					("308201db" + // ResponseBytes SEQUENCE
						"0609" + "2b0601050507300102" + // responseType OID = 1.3.6.1.5.5.7.48.1.2 = ???
						("048201cc" + // response OCTET STRING
							("308201c8" + // BasicOCSPResponse SEQUENCE
								("3081b1" + // tbsResponseData ResponseData SEQUENCE
									("a216" + // responderID byKey [2]
										("0414" + // KeyHash OCTETSTRING
											"0f80611c823161d52f28e78d4638b42ce1c6d9e2")) +
									("180f" + // producedAt GeneralizedTime
										"32303137313231393036353035325a") +
									("308185" + // SEQUENCE OF SingleResponse
										("308182" + // SingleResponse SEQUENCE
											("3049" + // CertID SEQUENCE
												("3009" + // hashAlgorithm AlgorithmIdentifier SEQUENCE
													"0605" + "2b0e03021a" + // OID: 1.3.14.3.2.26 (sha1)
													"0500") + // NULL
												("0414" + // issuerNameHash OCTET STRING
													"105fa67a80089db5279f35ce830b43889ea3c70d") +
												("0414" + // issuerKeyHash OCTET STRING
													"0f80611c823161d52f28e78d4638b42ce1c6d9e2") +
												("0210" + // certificateSerialNumber INTEGER
													"01af1efbdd5eae0952320b24fe6b5568")) +
											("a111" + // certStatus CHOICE = [1] revoked SEQUENCE
												("180f" + // revocationTime GeneralizedTime
													"32303136303930323231323834385a")) +
											("180f" + //  thisUpdate GeneralizedTime
												"32303137313231393036353035325a") +
											("a011" + // nextUpdate EXPLICIT[0]
												("180f" + // GeneralizedTime
													"32303137313232363036303535325a")))) +
									("300d" +
										"0609" + "2a864886f70d01010b" + // OID: 1.2.840.113549.1.1.11 sha256-with-rsa-signature
										"0500") + // NULL
									("03820101" + // signature BIT STRING
										"006c606b22a409123831ef30fc07e9a7" +
										"f70181b54cf01f743cc32c4da7dbf186" +
										"f22bae20dc721b20c869d9efb90e13c8" +
										"f7ab4fac4e70585626d9ea7689116fdc" +
										"15aba4e1b41a8eda2149db41b5e29f77" +
										"0d40006ed1eb7016385dca56c1acb355" +
										"b175031e846e6919002c1cf5177f285e" +
										"3f594c0a6b4c0cdce3fa739db89306cf" +
										"0255e6fbb24b86e5fa173d81af42e124" +
										"fd4efb92cfc4be09414a3e06dcfc98ea" +
										"9951c9e84d8ada1a995c7fb1c9b39237" +
										"2d8df14069aecce4845bd0760827e7de" +
										"06d7024bb9a6552a30506cc89e404322" +
										"c2fc05b0b42f28f975f44ca0da8c90e4" +
										"79f4ead03f90e8c7471a3130a82733b0" +
										"cb47c33a082e16f4a1503f66a3e7a59f" +
										"42"))))))),
			wantErr: "bad OCSP response type",
		},
		{
			desc:    "invalid ASN1",
			in:      "0000",
			wantErr: "asn1: structure error",
		},
		{
			desc: "invalid inner ASN1",
			in: ("3016" + // OCSPResponse SEQUENCE
				"0a0100" + // responseStatus ENUMERATED = successful(0)
				("a011" + // responseBytes [0] EXPLICIT
					("300f" + // ResponseBytes SEQUENCE
						"0609" + "2b0601050507300101" + // responseType OID = 1.3.6.1.5.5.7.48.1.1 = Basic Response
						("0402" + // response OCTET STRING
							"0000")))), // <invalid>
			wantErr: "asn1: structure error",
		},
		{
			desc: "multiple responses",
			in: ("3082026d" + // OCSPResponse SEQUENCE
				"0a0100" + // responseStatus ENUMERATED = successful(0)
				("a0820266" + // responseBytes [0] EXPLICIT
					("30820262" + // ResponseBytes SEQUENCE
						"0609" + "2b0601050507300101" + // responseType OID = 1.3.6.1.5.5.7.48.1.1 = Basic Response
						("04820253" + // response OCTET STRING
							("3082024f" + // BasicOCSPResponse SEQUENCE
								("30820137" + // tbsResponseData ResponseData SEQUENCE
									("a216" + // responderID byKey [2]
										("0414" + // KeyHash OCTETSTRING
											"0f80611c823161d52f28e78d4638b42ce1c6d9e2")) +
									("180f" + // producedAt GeneralizedTime
										"32303137313231393036353035325a") +
									("3082010a" + // SEQUENCE OF SingleResponse
										("308182" + // SingleResponse SEQUENCE
											("3049" + // CertID SEQUENCE
												("3009" + // hashAlgorithm AlgorithmIdentifier SEQUENCE
													"0605" + "2b0e03021a" + // OID: 1.3.14.3.2.26 (sha1)
													"0500") + // NULL
												("0414" + // issuerNameHash OCTET STRING
													"105fa67a80089db5279f35ce830b43889ea3c70d") +
												("0414" + // issuerKeyHash OCTET STRING
													"0f80611c823161d52f28e78d4638b42ce1c6d9e2") +
												("0210" + // certificateSerialNumber INTEGER
													"01af1efbdd5eae0952320b24fe6b5568")) +
											("a111" + // certStatus CHOICE = [1] revoked SEQUENCE
												("180f" + // revocationTime GeneralizedTime
													"32303136303930323231323834385a")) +
											("180f" + //  thisUpdate GeneralizedTime
												"32303137313231393036353035325a") +
											("a011" + // nextUpdate EXPLICIT[0]
												("180f" + // GeneralizedTime
													"32303137313232363036303535325a"))) +
										("308182" + // SingleResponse SEQUENCE
											("3049" + // CertID SEQUENCE
												("3009" + // hashAlgorithm AlgorithmIdentifier SEQUENCE
													"0605" + "2b0e03021a" + // OID: 1.3.14.3.2.26 (sha1)
													"0500") + // NULL
												("0414" + // issuerNameHash OCTET STRING
													"105fa67a80089db5279f35ce830b43889ea3c70d") +
												("0414" + // issuerKeyHash OCTET STRING
													"0f80611c823161d52f28e78d4638b42ce1c6d9e2") +
												("0210" + // certificateSerialNumber INTEGER
													"01af1efbdd5eae0952320b24fe6b5568")) +
											("a111" + // certStatus CHOICE = [1] revoked SEQUENCE
												("180f" + // revocationTime GeneralizedTime
													"32303136303930323231323834385a")) +
											("180f" + //  thisUpdate GeneralizedTime
												"32303137313231393036353035325a") +
											("a011" + // nextUpdate EXPLICIT[0]
												("180f" + // GeneralizedTime
													"32303137313232363036303535325a")))) +
									("300d" +
										"0609" + "2a864886f70d01010b" + // OID: 1.2.840.113549.1.1.11 sha256-with-rsa-signature
										"0500") + // NULL
									("03820101" + // signature BIT STRING
										"006c606b22a409123831ef30fc07e9a7" +
										"f70181b54cf01f743cc32c4da7dbf186" +
										"f22bae20dc721b20c869d9efb90e13c8" +
										"f7ab4fac4e70585626d9ea7689116fdc" +
										"15aba4e1b41a8eda2149db41b5e29f77" +
										"0d40006ed1eb7016385dca56c1acb355" +
										"b175031e846e6919002c1cf5177f285e" +
										"3f594c0a6b4c0cdce3fa739db89306cf" +
										"0255e6fbb24b86e5fa173d81af42e124" +
										"fd4efb92cfc4be09414a3e06dcfc98ea" +
										"9951c9e84d8ada1a995c7fb1c9b39237" +
										"2d8df14069aecce4845bd0760827e7de" +
										"06d7024bb9a6552a30506cc89e404322" +
										"c2fc05b0b42f28f975f44ca0da8c90e4" +
										"79f4ead03f90e8c7471a3130a82733b0" +
										"cb47c33a082e16f4a1503f66a3e7a59f" +
										"42"))))))),
			wantErr: "bad number of responses",
		},
		{
			desc: "invalid responderID byHash contents",
			in: ("308201e6" + // OCSPResponse SEQUENCE
				"0a0100" + // responseStatus ENUMERATED = successful(0)
				("a08201df" + // responseBytes [0] EXPLICIT
					("308201db" + // ResponseBytes SEQUENCE
						"0609" + "2b0601050507300101" + // responseType OID = 1.3.6.1.5.5.7.48.1.1 = Basic Response
						("048201cc" + // response OCTET STRING
							("308201c8" + // BasicOCSPResponse SEQUENCE
								("3081b1" + // tbsResponseData ResponseData SEQUENCE
									("a216" + // responderID byHash [2]
										("0000" + "0f80611c823161d52f28e78d4638b42ce1c6d9e2")) +
									("180f" + // producedAt GeneralizedTime
										"32303137313231393036353035325a") +
									("308185" + // SEQUENCE OF SingleResponse
										("308182" + // SingleResponse SEQUENCE
											("3049" + // CertID SEQUENCE
												("3009" + // hashAlgorithm AlgorithmIdentifier SEQUENCE
													"0605" + "2b0e03021a" + // OID: 1.3.14.3.2.26 (sha1)
													"0500") + // NULL
												("0414" + // issuerNameHash OCTET STRING
													"105fa67a80089db5279f35ce830b43889ea3c70d") +
												("0414" + // issuerKeyHash OCTET STRING
													"0f80611c823161d52f28e78d4638b42ce1c6d9e2") +
												("0210" + // certificateSerialNumber INTEGER
													"01af1efbdd5eae0952320b24fe6b5568")) +
											("a111" + // certStatus CHOICE = [1] revoked SEQUENCE
												("180f" + // revocationTime GeneralizedTime
													"32303136303930323231323834385a")) +
											("180f" + //  thisUpdate GeneralizedTime
												"32303137313231393036353035325a") +
											("a011" + // nextUpdate EXPLICIT[0]
												("180f" + // GeneralizedTime
													"32303137313232363036303535325a")))) +
									("300d" +
										"0609" + "2a864886f70d01010b" + // OID: 1.2.840.113549.1.1.11 sha256-with-rsa-signature
										"0500") + // NULL
									("03820101" + // signature BIT STRING
										"006c606b22a409123831ef30fc07e9a7" +
										"f70181b54cf01f743cc32c4da7dbf186" +
										"f22bae20dc721b20c869d9efb90e13c8" +
										"f7ab4fac4e70585626d9ea7689116fdc" +
										"15aba4e1b41a8eda2149db41b5e29f77" +
										"0d40006ed1eb7016385dca56c1acb355" +
										"b175031e846e6919002c1cf5177f285e" +
										"3f594c0a6b4c0cdce3fa739db89306cf" +
										"0255e6fbb24b86e5fa173d81af42e124" +
										"fd4efb92cfc4be09414a3e06dcfc98ea" +
										"9951c9e84d8ada1a995c7fb1c9b39237" +
										"2d8df14069aecce4845bd0760827e7de" +
										"06d7024bb9a6552a30506cc89e404322" +
										"c2fc05b0b42f28f975f44ca0da8c90e4" +
										"79f4ead03f90e8c7471a3130a82733b0" +
										"cb47c33a082e16f4a1503f66a3e7a59f" +
										"42"))))))),
			wantErr: "invalid responder key hash",
		},
		{
			desc: "invalid responderID CHOICE",
			in: ("308201e6" + // OCSPResponse SEQUENCE
				"0a0100" + // responseStatus ENUMERATED = successful(0)
				("a08201df" + // responseBytes [0] EXPLICIT
					("308201db" + // ResponseBytes SEQUENCE
						"0609" + "2b0601050507300101" + // responseType OID = 1.3.6.1.5.5.7.48.1.1 = Basic Response
						("048201cc" + // response OCTET STRING
							("308201c8" + // BasicOCSPResponse SEQUENCE
								("3081b1" + // tbsResponseData ResponseData SEQUENCE
									("a316" + // responderID <invalid> [3]
										("0414" + // KeyHash OCTETSTRING
											"0f80611c823161d52f28e78d4638b42ce1c6d9e2")) +
									("180f" + // producedAt GeneralizedTime
										"32303137313231393036353035325a") +
									("308185" + // SEQUENCE OF SingleResponse
										("308182" + // SingleResponse SEQUENCE
											("3049" + // CertID SEQUENCE
												("3009" + // hashAlgorithm AlgorithmIdentifier SEQUENCE
													"0605" + "2b0e03021a" + // OID: 1.3.14.3.2.26 (sha1)
													"0500") + // NULL
												("0414" + // issuerNameHash OCTET STRING
													"105fa67a80089db5279f35ce830b43889ea3c70d") +
												("0414" + // issuerKeyHash OCTET STRING
													"0f80611c823161d52f28e78d4638b42ce1c6d9e2") +
												("0210" + // certificateSerialNumber INTEGER
													"01af1efbdd5eae0952320b24fe6b5568")) +
											("a111" + // certStatus CHOICE = [1] revoked SEQUENCE
												("180f" + // revocationTime GeneralizedTime
													"32303136303930323231323834385a")) +
											("180f" + //  thisUpdate GeneralizedTime
												"32303137313231393036353035325a") +
											("a011" + // nextUpdate EXPLICIT[0]
												("180f" + // GeneralizedTime
													"32303137313232363036303535325a")))) +
									("300d" +
										"0609" + "2a864886f70d01010b" + // OID: 1.2.840.113549.1.1.11 sha256-with-rsa-signature
										"0500") + // NULL
									("03820101" + // signature BIT STRING
										"006c606b22a409123831ef30fc07e9a7" +
										"f70181b54cf01f743cc32c4da7dbf186" +
										"f22bae20dc721b20c869d9efb90e13c8" +
										"f7ab4fac4e70585626d9ea7689116fdc" +
										"15aba4e1b41a8eda2149db41b5e29f77" +
										"0d40006ed1eb7016385dca56c1acb355" +
										"b175031e846e6919002c1cf5177f285e" +
										"3f594c0a6b4c0cdce3fa739db89306cf" +
										"0255e6fbb24b86e5fa173d81af42e124" +
										"fd4efb92cfc4be09414a3e06dcfc98ea" +
										"9951c9e84d8ada1a995c7fb1c9b39237" +
										"2d8df14069aecce4845bd0760827e7de" +
										"06d7024bb9a6552a30506cc89e404322" +
										"c2fc05b0b42f28f975f44ca0da8c90e4" +
										"79f4ead03f90e8c7471a3130a82733b0" +
										"cb47c33a082e16f4a1503f66a3e7a59f" +
										"42"))))))),
			wantErr: "invalid responder id tag",
		},
	}
	for _, test := range tests {
		data, _ := hex.DecodeString(test.in)
		got, err := ParseResponse(data, nil)
		if err != nil {
			if test.wantErr == "" {
				t.Errorf("ParseResponse(%s)=nil,%v; want _,nil", test.desc, err)
			} else if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("ParseResponse(%s)=nil,%v; want _,err containing %q", test.desc, err, test.wantErr)
			}
			continue
		}
		if test.wantErr != "" {
			t.Errorf("ParseResponse(%s)=%+v,nil; want nil, err containing %q", test.desc, got, test.wantErr)
			continue
		}
		// Only check key fields so the test data isn't too voluminous.
		if got.Status != test.want.Status {
			t.Errorf("ParseResponse(%s).Status=%v; want %v", test.desc, got.Status, test.want.Status)
		}
		if got.SerialNumber.Cmp(test.want.SerialNumber) != 0 {
			t.Errorf("ParseResponse(%s).SerialNumber=%v; want %v", test.desc, got.SerialNumber, test.want.SerialNumber)
		}
		if !got.ProducedAt.Equal(test.want.ProducedAt) {
			t.Errorf("ParseResponse(%s).ProducedAt=%v; want %v", test.desc, got.ProducedAt, test.want.ProducedAt)
		}
		if !got.ThisUpdate.Equal(test.want.ThisUpdate) {
			t.Errorf("ParseResponse(%s).ThisUpdate=%v; want %v", test.desc, got.ThisUpdate, test.want.ThisUpdate)
		}
		if !got.NextUpdate.Equal(test.want.NextUpdate) {
			t.Errorf("ParseResponse(%s).NextUpdate=%v; want %v", test.desc, got.NextUpdate, test.want.NextUpdate)
		}
		if got.SignatureAlgorithm != test.want.SignatureAlgorithm {
			t.Errorf("ParseResponse(%s).SignatureAlgorithm=%v; want %v", test.desc, got.SignatureAlgorithm, test.want.SignatureAlgorithm)
		}
		if got.IssuerHash != test.want.IssuerHash {
			t.Errorf("ParseResponse(%s).IssuerHash=%v; want %v", test.desc, got.IssuerHash, test.want.IssuerHash)
		}
	}
}

func TestOCSPResponse(t *testing.T) {
	leafCert, _ := hex.DecodeString(leafCertHex)
	leaf, err := x509.ParseCertificate(leafCert)
	if err != nil {
		t.Fatal(err)
	}

	issuerCert, _ := hex.DecodeString(issuerCertHex)
	issuer, err := x509.ParseCertificate(issuerCert)
	if err != nil {
		t.Fatal(err)
	}

	responderCert, _ := hex.DecodeString(responderCertHex)
	responder, err := x509.ParseCertificate(responderCert)
	if err != nil {
		t.Fatal(err)
	}

	responderPrivateKeyDER, _ := hex.DecodeString(responderPrivateKeyHex)
	responderPrivateKey, err := x509.ParsePKCS1PrivateKey(responderPrivateKeyDER)
	if err != nil {
		t.Fatal(err)
	}

	extensionBytes, _ := hex.DecodeString(ocspExtensionValueHex)
	extensions := []pkix.Extension{
		{
			Id:       ocspExtensionOID,
			Critical: false,
			Value:    extensionBytes,
		},
	}

	thisUpdate := time.Date(2010, 7, 7, 15, 1, 5, 0, time.UTC)
	nextUpdate := time.Date(2010, 7, 7, 18, 35, 17, 0, time.UTC)
	template := Response{
		Status:           Revoked,
		SerialNumber:     leaf.SerialNumber,
		ThisUpdate:       thisUpdate,
		NextUpdate:       nextUpdate,
		RevokedAt:        thisUpdate,
		RevocationReason: KeyCompromise,
		Certificate:      responder,
		ExtraExtensions:  extensions,
	}

	template.IssuerHash = crypto.MD5
	_, err = CreateResponse(issuer, responder, template, responderPrivateKey)
	if err == nil {
		t.Fatal("CreateResponse didn't fail with non-valid template.IssuerHash value crypto.MD5")
	}

	testCases := []struct {
		name       string
		issuerHash crypto.Hash
	}{
		{"Zero value", 0},
		{"crypto.SHA1", crypto.SHA1},
		{"crypto.SHA256", crypto.SHA256},
		{"crypto.SHA384", crypto.SHA384},
		{"crypto.SHA512", crypto.SHA512},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			template.IssuerHash = tc.issuerHash
			responseBytes, err := CreateResponse(issuer, responder, template, responderPrivateKey)
			if err != nil {
				t.Fatalf("CreateResponse failed: %s", err)
			}

			resp, err := ParseResponse(responseBytes, nil)
			if err != nil {
				t.Fatalf("ParseResponse failed: %s", err)
			}

			if !reflect.DeepEqual(resp.ThisUpdate, template.ThisUpdate) {
				t.Errorf("resp.ThisUpdate: got %v, want %v", resp.ThisUpdate, template.ThisUpdate)
			}

			if !reflect.DeepEqual(resp.NextUpdate, template.NextUpdate) {
				t.Errorf("resp.NextUpdate: got %v, want %v", resp.NextUpdate, template.NextUpdate)
			}

			if !reflect.DeepEqual(resp.RevokedAt, template.RevokedAt) {
				t.Errorf("resp.RevokedAt: got %v, want %v", resp.RevokedAt, template.RevokedAt)
			}

			if !reflect.DeepEqual(resp.Extensions, template.ExtraExtensions) {
				t.Errorf("resp.Extensions: got %v, want %v", resp.Extensions, template.ExtraExtensions)
			}

			delay := time.Since(resp.ProducedAt)
			if delay < -time.Hour || delay > time.Hour {
				t.Errorf("resp.ProducedAt: got %s, want close to current time (%s)", resp.ProducedAt, time.Now())
			}

			if resp.Status != template.Status {
				t.Errorf("resp.Status: got %d, want %d", resp.Status, template.Status)
			}

			if resp.SerialNumber.Cmp(template.SerialNumber) != 0 {
				t.Errorf("resp.SerialNumber: got %x, want %x", resp.SerialNumber, template.SerialNumber)
			}

			if resp.RevocationReason != template.RevocationReason {
				t.Errorf("resp.RevocationReason: got %d, want %d", resp.RevocationReason, template.RevocationReason)
			}

			expectedHash := tc.issuerHash
			if tc.issuerHash == 0 {
				expectedHash = crypto.SHA1
			}

			if resp.IssuerHash != expectedHash {
				t.Errorf("resp.IssuerHash: got %d, want %d", resp.IssuerHash, expectedHash)
			}
		})
	}
}

func TestErrorResponse(t *testing.T) {
	responseBytes, _ := hex.DecodeString(errorResponseHex)
	_, err := ParseResponse(responseBytes, nil)

	respErr, ok := err.(ResponseError)
	if !ok {
		t.Fatalf("expected ResponseError from ParseResponse but got %#v", err)
	}
	if got, want := respErr.Error(), "ocsp: error from server: malformed"; got != want {
		t.Errorf("ResponseError.Error()=%q, want %q", got, want)
	}
	if respErr.Status != Malformed {
		t.Errorf("expected Malformed status from ParseResponse but got %d", respErr.Status)
	}
}

func TestOCSPDecodeMultiResponse(t *testing.T) {
	inclCert, _ := hex.DecodeString(ocspMultiResponseCertHex)
	cert, err := x509.ParseCertificate(inclCert)
	if err != nil {
		t.Fatal(err)
	}

	responseBytes, _ := hex.DecodeString(ocspMultiResponseHex)
	resp, err := ParseResponseForCert(responseBytes, cert, nil)
	if err != nil {
		t.Fatal(err)
	}

	if resp.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("resp.SerialNumber: got %x, want %x", resp.SerialNumber, cert.SerialNumber)
	}
}

func TestOCSPDecodeMultiResponseWithoutMatchingCert(t *testing.T) {
	wrongCert, _ := hex.DecodeString(startComHex)
	cert, err := x509.ParseCertificate(wrongCert)
	if err != nil {
		t.Fatal(err)
	}

	responseBytes, _ := hex.DecodeString(ocspMultiResponseHex)
	_, err = ParseResponseForCert(responseBytes, cert, nil)
	want := ParseError("no response matching the supplied certificate")
	if err != want {
		t.Errorf("err: got %q, want %q", err, want)
	}
}

// This OCSP response was taken from Thawte's public OCSP responder.
// To recreate:
//   $ openssl s_client -tls1 -showcerts -servername www.google.com -connect www.google.com:443
// Copy and paste the first certificate into /tmp/cert.crt and the second into
// /tmp/intermediate.crt
//   $ openssl ocsp -issuer /tmp/intermediate.crt -cert /tmp/cert.crt -url http://ocsp.thawte.com -resp_text -respout /tmp/ocsp.der
// Then hex encode the result:
//   $ python -c 'print file("/tmp/ocsp.der", "r").read().encode("hex")'

const ocspResponseHex = "308206bc0a0100a08206b5308206b106092b0601050507300101048206a23082069e3081" +
	"c9a14e304c310b300906035504061302494c31163014060355040a130d5374617274436f" +
	"6d204c74642e312530230603550403131c5374617274436f6d20436c6173732031204f43" +
	"5350205369676e6572180f32303130303730373137333531375a30663064303c30090605" +
	"2b0e03021a050004146568874f40750f016a3475625e1f5c93e5a26d580414eb4234d098" +
	"b0ab9ff41b6b08f7cc642eef0e2c45020301d0fa8000180f323031303037303731353031" +
	"30355aa011180f32303130303730373138333531375a300d06092a864886f70d01010505" +
	"000382010100ab557ff070d1d7cebbb5f0ec91a15c3fed22eb2e1b8244f1b84545f013a4" +
	"fb46214c5e3fbfbebb8a56acc2b9db19f68fd3c3201046b3824d5ba689f99864328710cb" +
	"467195eb37d84f539e49f859316b32964dc3e47e36814ce94d6c56dd02733b1d0802f7ff" +
	"4eebdbbd2927dcf580f16cbc290f91e81b53cb365e7223f1d6e20a88ea064104875e0145" +
	"672b20fc14829d51ca122f5f5d77d3ad6c83889c55c7dc43680ba2fe3cef8b05dbcabdc0" +
	"d3e09aaf9725597f8c858c2fa38c0d6aed2e6318194420dd1a1137445d13e1c97ab47896" +
	"17a4e08925f46f867b72e3a4dc1f08cb870b2b0717f7207faa0ac512e628a029aba7457a" +
	"e63dcf3281e2162d9349a08204ba308204b6308204b23082039aa003020102020101300d" +
	"06092a864886f70d010105050030818c310b300906035504061302494c31163014060355" +
	"040a130d5374617274436f6d204c74642e312b3029060355040b13225365637572652044" +
	"69676974616c204365727469666963617465205369676e696e6731383036060355040313" +
	"2f5374617274436f6d20436c6173732031205072696d61727920496e7465726d65646961" +
	"746520536572766572204341301e170d3037313032353030323330365a170d3132313032" +
	"333030323330365a304c310b300906035504061302494c31163014060355040a130d5374" +
	"617274436f6d204c74642e312530230603550403131c5374617274436f6d20436c617373" +
	"2031204f435350205369676e657230820122300d06092a864886f70d0101010500038201" +
	"0f003082010a0282010100b9561b4c45318717178084e96e178df2255e18ed8d8ecc7c2b" +
	"7b51a6c1c2e6bf0aa3603066f132fe10ae97b50e99fa24b83fc53dd2777496387d14e1c3" +
	"a9b6a4933e2ac12413d085570a95b8147414a0bc007c7bcf222446ef7f1a156d7ea1c577" +
	"fc5f0facdfd42eb0f5974990cb2f5cefebceef4d1bdc7ae5c1075c5a99a93171f2b0845b" +
	"4ff0864e973fcfe32f9d7511ff87a3e943410c90a4493a306b6944359340a9ca96f02b66" +
	"ce67f028df2980a6aaee8d5d5d452b8b0eb93f923cc1e23fcccbdbe7ffcb114d08fa7a6a" +
	"3c404f825d1a0e715935cf623a8c7b59670014ed0622f6089a9447a7a19010f7fe58f841" +
	"29a2765ea367824d1c3bb2fda308530203010001a382015c30820158300c0603551d1301" +
	"01ff04023000300b0603551d0f0404030203a8301e0603551d250417301506082b060105" +
	"0507030906092b0601050507300105301d0603551d0e0416041445e0a36695414c5dd449" +
	"bc00e33cdcdbd2343e173081a80603551d230481a030819d8014eb4234d098b0ab9ff41b" +
	"6b08f7cc642eef0e2c45a18181a47f307d310b300906035504061302494c311630140603" +
	"55040a130d5374617274436f6d204c74642e312b3029060355040b132253656375726520" +
	"4469676974616c204365727469666963617465205369676e696e67312930270603550403" +
	"13205374617274436f6d2043657274696669636174696f6e20417574686f726974798201" +
	"0a30230603551d12041c301a8618687474703a2f2f7777772e737461727473736c2e636f" +
	"6d2f302c06096086480186f842010d041f161d5374617274436f6d205265766f63617469" +
	"6f6e20417574686f72697479300d06092a864886f70d01010505000382010100182d2215" +
	"8f0fc0291324fa8574c49bb8ff2835085adcbf7b7fc4191c397ab6951328253fffe1e5ec" +
	"2a7da0d50fca1a404e6968481366939e666c0a6209073eca57973e2fefa9ed1718e8176f" +
	"1d85527ff522c08db702e3b2b180f1cbff05d98128252cf0f450f7dd2772f4188047f19d" +
	"c85317366f94bc52d60f453a550af58e308aaab00ced33040b62bf37f5b1ab2a4f7f0f80" +
	"f763bf4d707bc8841d7ad9385ee2a4244469260b6f2bf085977af9074796048ecc2f9d48" +
	"a1d24ce16e41a9941568fec5b42771e118f16c106a54ccc339a4b02166445a167902e75e" +
	"6d8620b0825dcd18a069b90fd851d10fa8effd409deec02860d26d8d833f304b10669b42"

const startComResponderCertHex = "308204b23082039aa003020102020101300d06092a864886f70d010105050030818c310b" +
	"300906035504061302494c31163014060355040a130d5374617274436f6d204c74642e31" +
	"2b3029060355040b1322536563757265204469676974616c204365727469666963617465" +
	"205369676e696e67313830360603550403132f5374617274436f6d20436c617373203120" +
	"5072696d61727920496e7465726d65646961746520536572766572204341301e170d3037" +
	"313032353030323330365a170d3132313032333030323330365a304c310b300906035504" +
	"061302494c31163014060355040a130d5374617274436f6d204c74642e31253023060355" +
	"0403131c5374617274436f6d20436c6173732031204f435350205369676e657230820122" +
	"300d06092a864886f70d01010105000382010f003082010a0282010100b9561b4c453187" +
	"17178084e96e178df2255e18ed8d8ecc7c2b7b51a6c1c2e6bf0aa3603066f132fe10ae97" +
	"b50e99fa24b83fc53dd2777496387d14e1c3a9b6a4933e2ac12413d085570a95b8147414" +
	"a0bc007c7bcf222446ef7f1a156d7ea1c577fc5f0facdfd42eb0f5974990cb2f5cefebce" +
	"ef4d1bdc7ae5c1075c5a99a93171f2b0845b4ff0864e973fcfe32f9d7511ff87a3e94341" +
	"0c90a4493a306b6944359340a9ca96f02b66ce67f028df2980a6aaee8d5d5d452b8b0eb9" +
	"3f923cc1e23fcccbdbe7ffcb114d08fa7a6a3c404f825d1a0e715935cf623a8c7b596700" +
	"14ed0622f6089a9447a7a19010f7fe58f84129a2765ea367824d1c3bb2fda30853020301" +
	"0001a382015c30820158300c0603551d130101ff04023000300b0603551d0f0404030203" +
	"a8301e0603551d250417301506082b0601050507030906092b0601050507300105301d06" +
	"03551d0e0416041445e0a36695414c5dd449bc00e33cdcdbd2343e173081a80603551d23" +
	"0481a030819d8014eb4234d098b0ab9ff41b6b08f7cc642eef0e2c45a18181a47f307d31" +
	"0b300906035504061302494c31163014060355040a130d5374617274436f6d204c74642e" +
	"312b3029060355040b1322536563757265204469676974616c2043657274696669636174" +
	"65205369676e696e6731293027060355040313205374617274436f6d2043657274696669" +
	"636174696f6e20417574686f7269747982010a30230603551d12041c301a861868747470" +
	"3a2f2f7777772e737461727473736c2e636f6d2f302c06096086480186f842010d041f16" +
	"1d5374617274436f6d205265766f636174696f6e20417574686f72697479300d06092a86" +
	"4886f70d01010505000382010100182d22158f0fc0291324fa8574c49bb8ff2835085adc" +
	"bf7b7fc4191c397ab6951328253fffe1e5ec2a7da0d50fca1a404e6968481366939e666c" +
	"0a6209073eca57973e2fefa9ed1718e8176f1d85527ff522c08db702e3b2b180f1cbff05" +
	"d98128252cf0f450f7dd2772f4188047f19dc85317366f94bc52d60f453a550af58e308a" +
	"aab00ced33040b62bf37f5b1ab2a4f7f0f80f763bf4d707bc8841d7ad9385ee2a4244469" +
	"260b6f2bf085977af9074796048ecc2f9d48a1d24ce16e41a9941568fec5b42771e118f1" +
	"6c106a54ccc339a4b02166445a167902e75e6d8620b0825dcd18a069b90fd851d10fa8ef" +
	"fd409deec02860d26d8d833f304b10669b42"

const startComHex = "308206343082041ca003020102020118300d06092a864886f70d0101050500307d310b30" +
	"0906035504061302494c31163014060355040a130d5374617274436f6d204c74642e312b" +
	"3029060355040b1322536563757265204469676974616c20436572746966696361746520" +
	"5369676e696e6731293027060355040313205374617274436f6d20436572746966696361" +
	"74696f6e20417574686f72697479301e170d3037313032343230353431375a170d313731" +
	"3032343230353431375a30818c310b300906035504061302494c31163014060355040a13" +
	"0d5374617274436f6d204c74642e312b3029060355040b13225365637572652044696769" +
	"74616c204365727469666963617465205369676e696e67313830360603550403132f5374" +
	"617274436f6d20436c6173732031205072696d61727920496e7465726d65646961746520" +
	"53657276657220434130820122300d06092a864886f70d01010105000382010f00308201" +
	"0a0282010100b689c6acef09527807ac9263d0f44418188480561f91aee187fa3250b4d3" +
	"4706f0e6075f700e10f71dc0ce103634855a0f92ac83c6ac58523fba38e8fce7a724e240" +
	"a60876c0926e9e2a6d4d3f6e61200adb59ded27d63b33e46fefa215118d7cd30a6ed076e" +
	"3b7087b4f9faebee823c056f92f7a4dc0a301e9373fe07cad75f809d225852ae06da8b87" +
	"2369b0e42ad8ea83d2bdf371db705a280faf5a387045123f304dcd3baf17e50fcba0a95d" +
	"48aab16150cb34cd3c5cc30be810c08c9bf0030362feb26c3e720eee1c432ac9480e5739" +
	"c43121c810c12c87fe5495521f523c31129b7fe7c0a0a559d5e28f3ef0d5a8e1d77031a9" +
	"c4b3cfaf6d532f06f4a70203010001a38201ad308201a9300f0603551d130101ff040530" +
	"030101ff300e0603551d0f0101ff040403020106301d0603551d0e04160414eb4234d098" +
	"b0ab9ff41b6b08f7cc642eef0e2c45301f0603551d230418301680144e0bef1aa4405ba5" +
	"17698730ca346843d041aef2306606082b06010505070101045a3058302706082b060105" +
	"05073001861b687474703a2f2f6f6373702e737461727473736c2e636f6d2f6361302d06" +
	"082b060105050730028621687474703a2f2f7777772e737461727473736c2e636f6d2f73" +
	"667363612e637274305b0603551d1f045430523027a025a0238621687474703a2f2f7777" +
	"772e737461727473736c2e636f6d2f73667363612e63726c3027a025a023862168747470" +
	"3a2f2f63726c2e737461727473736c2e636f6d2f73667363612e63726c3081800603551d" +
	"20047930773075060b2b0601040181b5370102013066302e06082b060105050702011622" +
	"687474703a2f2f7777772e737461727473736c2e636f6d2f706f6c6963792e7064663034" +
	"06082b060105050702011628687474703a2f2f7777772e737461727473736c2e636f6d2f" +
	"696e7465726d6564696174652e706466300d06092a864886f70d01010505000382020100" +
	"2109493ea5886ee00b8b48da314d8ff75657a2e1d36257e9b556f38545753be5501f048b" +
	"e6a05a3ee700ae85d0fbff200364cbad02e1c69172f8a34dd6dee8cc3fa18aa2e37c37a7" +
	"c64f8f35d6f4d66e067bdd21d9cf56ffcb302249fe8904f385e5aaf1e71fe875904dddf9" +
	"46f74234f745580c110d84b0c6da5d3ef9019ee7e1da5595be741c7bfc4d144fac7e5547" +
	"7d7bf4a50d491e95e8f712c1ccff76a62547d0f37535be97b75816ebaa5c786fec5330af" +
	"ea044dcca902e3f0b60412f630b1113d904e5664d7dc3c435f7339ef4baf87ebf6fe6888" +
	"4472ead207c669b0c1a18bef1749d761b145485f3b2021e95bb2ccf4d7e931f50b15613b" +
	"7a94e3ebd9bc7f94ae6ae3626296a8647cb887f399327e92a252bebbf865cfc9f230fc8b" +
	"c1c2a696d75f89e15c3480f58f47072fb491bfb1a27e5f4b5ad05b9f248605515a690365" +
	"434971c5e06f94346bf61bd8a9b04c7e53eb8f48dfca33b548fa364a1a53a6330cd089cd" +
	"4915cd89313c90c072d7654b52358a461144b93d8e2865a63e799e5c084429adb035112e" +
	"214eb8d2e7103e5d8483b3c3c2e4d2c6fd094b7409ddf1b3d3193e800da20b19f038e7c5" +
	"c2afe223db61e29d5c6e2089492e236ab262c145b49faf8ba7f1223bf87de290d07a19fb" +
	"4a4ce3d27d5f4a8303ed27d6239e6b8db459a2d9ef6c8229dd75193c3f4c108defbb7527" +
	"d2ae83a7a8ce5ba7"

const ocspResponseWithoutCertHex = "308201d40a0100a08201cd308201c906092b0601050507300101048201ba3082" +
	"01b630819fa2160414884451ff502a695e2d88f421bad90cf2cecbea7c180f3230313330" +
	"3631383037323434335a30743072304a300906052b0e03021a0500041448b60d38238df8" +
	"456e4ee5843ea394111802979f0414884451ff502a695e2d88f421bad90cf2cecbea7c02" +
	"1100f78b13b946fc9635d8ab49de9d2148218000180f3230313330363138303732343433" +
	"5aa011180f32303133303632323037323434335a300d06092a864886f70d010105050003" +
	"82010100103e18b3d297a5e7a6c07a4fc52ac46a15c0eba96f3be17f0ffe84de5b8c8e05" +
	"5a8f577586a849dc4abd6440eb6fedde4622451e2823c1cbf3558b4e8184959c9fe96eff" +
	"8bc5f95866c58c6d087519faabfdae37e11d9874f1bc0db292208f645dd848185e4dd38b" +
	"6a8547dfa7b74d514a8470015719064d35476b95bebb03d4d2845c5ca15202d2784878f2" +
	"0f904c24f09736f044609e9c271381713400e563023d212db422236440c6f377bbf24b2b" +
	"9e7dec8698e36a8df68b7592ad3489fb2937afb90eb85d2aa96b81c94c25057dbd4759d9" +
	"20a1a65c7f0b6427a224b3c98edd96b9b61f706099951188b0289555ad30a216fb774651" +
	"5a35fca2e054dfa8"

// PKIX nonce extension
var ocspExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
var ocspExtensionValueHex = "0403000000"

const ocspResponseWithCriticalExtensionHex = "308204fe0a0100a08204f7308204f306092b0601050507300101048204e4308204e03081" +
	"dba003020100a11b3019311730150603550403130e4f43535020526573706f6e64657218" +
	"0f32303136303130343137303130305a3081a53081a23049300906052b0e03021a050004" +
	"14c0fe0278fc99188891b3f212e9c7e1b21ab7bfc004140dfc1df0a9e0f01ce7f2b21317" +
	"7e6f8d157cd4f60210017f77deb3bcbb235d44ccc7dba62e72a116180f32303130303730" +
	"373135303130355aa0030a0101180f32303130303730373135303130355aa011180f3230" +
	"3130303730373138333531375aa1193017301506092b06010505073001020101ff040504" +
	"03000000300d06092a864886f70d01010b0500038201010031c730ca60a7a0d92d8e4010" +
	"911b469de95b4d27e89de6537552436237967694f76f701cf6b45c932bd308bca4a8d092" +
	"5c604ba94796903091d9e6c000178e72c1f0a24a277dd262835af5d17d3f9d7869606c9f" +
	"e7c8e708a41645699895beee38bfa63bb46296683761c5d1d65439b8ab868dc3017c9eeb" +
	"b70b82dbf3a31c55b457d48bb9e82b335ed49f445042eaf606b06a3e0639824924c89c63" +
	"eccddfe85e6694314138b2536f5e15e07085d0f6e26d4b2f8244bab0d70de07283ac6384" +
	"a0501fc3dea7cf0adfd4c7f34871080900e252ddc403e3f0265f2a704af905d3727504ed" +
	"28f3214a219d898a022463c78439799ca81c8cbafdbcec34ea937cd6a08202ea308202e6" +
	"308202e2308201caa003020102020101300d06092a864886f70d01010b05003019311730" +
	"150603550403130e4f43535020526573706f6e646572301e170d31353031333031353530" +
	"33335a170d3136303133303135353033335a3019311730150603550403130e4f43535020" +
	"526573706f6e64657230820122300d06092a864886f70d01010105000382010f00308201" +
	"0a0282010100e8155f2d3e6f2e8d14c62a788bd462f9f844e7a6977c83ef1099f0f6616e" +
	"c5265b56f356e62c5400f0b06a2e7945a82752c636df32a895152d6074df1701dc6ccfbc" +
	"bec75a70bd2b55ae2be7e6cad3b5fd4cd5b7790ab401a436d3f5f346074ffde8a99d5b72" +
	"3350f0a112076614b12ef79c78991b119453445acf2416ab0046b540db14c9fc0f27b898" +
	"9ad0f63aa4b8aefc91aa8a72160c36307c60fec78a93d3fddf4259902aa77e7332971c7d" +
	"285b6a04f648993c6922a3e9da9adf5f81508c3228791843e5d49f24db2f1290bafd97e6" +
	"55b1049a199f652cd603c4fafa330c390b0da78fbbc67e8fa021cbd74eb96222b12ace31" +
	"a77dcf920334dc94581b0203010001a3353033300e0603551d0f0101ff04040302078030" +
	"130603551d25040c300a06082b06010505070309300c0603551d130101ff04023000300d" +
	"06092a864886f70d01010b05000382010100718012761b5063e18f0dc44644d8e6ab8612" +
	"31c15fd5357805425d82aec1de85bf6d3e30fce205e3e3b8b795bbe52e40a439286d2288" +
	"9064f4aeeb150359b9425f1da51b3a5c939018555d13ac42c565a0603786a919328f3267" +
	"09dce52c22ad958ecb7873b9771d1148b1c4be2efe80ba868919fc9f68b6090c2f33c156" +
	"d67156e42766a50b5d51e79637b7e58af74c2a951b1e642fa7741fec982cc937de37eff5" +
	"9e2005d5939bfc031589ca143e6e8ab83f40ee08cc20a6b4a95a318352c28d18528dcaf9" +
	"66705de17afa19d6e8ae91ddf33179d16ebb6ac2c69cae8373d408ebf8c55308be6c04d9" +
	"3a25439a94299a65a709756c7a3e568be049d5c38839"

const ocspResponseWithExtensionHex = "308204fb0a0100a08204f4308204f006092b0601050507300101048204e1308204dd3081" +
	"d8a003020100a11b3019311730150603550403130e4f43535020526573706f6e64657218" +
	"0f32303136303130343136353930305a3081a230819f3049300906052b0e03021a050004" +
	"14c0fe0278fc99188891b3f212e9c7e1b21ab7bfc004140dfc1df0a9e0f01ce7f2b21317" +
	"7e6f8d157cd4f60210017f77deb3bcbb235d44ccc7dba62e72a116180f32303130303730" +
	"373135303130355aa0030a0101180f32303130303730373135303130355aa011180f3230" +
	"3130303730373138333531375aa1163014301206092b0601050507300102040504030000" +
	"00300d06092a864886f70d01010b05000382010100c09a33e0b2324c852421bb83f85ac9" +
	"9113f5426012bd2d2279a8166e9241d18a33c870894250622ffc7ed0c4601b16d624f90b" +
	"779265442cdb6868cf40ab304ab4b66e7315ed02cf663b1601d1d4751772b31bc299db23" +
	"9aebac78ed6797c06ed815a7a8d18d63cfbb609cafb47ec2e89e37db255216eb09307848" +
	"d01be0a3e943653c78212b96ff524b74c9ec456b17cdfb950cc97645c577b2e09ff41dde" +
	"b03afb3adaa381cc0f7c1d95663ef22a0f72f2c45613ae8e2b2d1efc96e8463c7d1d8a1d" +
	"7e3b35df8fe73a301fc3f804b942b2b3afa337ff105fc1462b7b1c1d75eb4566c8665e59" +
	"f80393b0adbf8004ff6c3327ed34f007cb4a3348a7d55e06e3a08202ea308202e6308202" +
	"e2308201caa003020102020101300d06092a864886f70d01010b05003019311730150603" +
	"550403130e4f43535020526573706f6e646572301e170d3135303133303135353033335a" +
	"170d3136303133303135353033335a3019311730150603550403130e4f43535020526573" +
	"706f6e64657230820122300d06092a864886f70d01010105000382010f003082010a0282" +
	"010100e8155f2d3e6f2e8d14c62a788bd462f9f844e7a6977c83ef1099f0f6616ec5265b" +
	"56f356e62c5400f0b06a2e7945a82752c636df32a895152d6074df1701dc6ccfbcbec75a" +
	"70bd2b55ae2be7e6cad3b5fd4cd5b7790ab401a436d3f5f346074ffde8a99d5b723350f0" +
	"a112076614b12ef79c78991b119453445acf2416ab0046b540db14c9fc0f27b8989ad0f6" +
	"3aa4b8aefc91aa8a72160c36307c60fec78a93d3fddf4259902aa77e7332971c7d285b6a" +
	"04f648993c6922a3e9da9adf5f81508c3228791843e5d49f24db2f1290bafd97e655b104" +
	"9a199f652cd603c4fafa330c390b0da78fbbc67e8fa021cbd74eb96222b12ace31a77dcf" +
	"920334dc94581b0203010001a3353033300e0603551d0f0101ff04040302078030130603" +
	"551d25040c300a06082b06010505070309300c0603551d130101ff04023000300d06092a" +
	"864886f70d01010b05000382010100718012761b5063e18f0dc44644d8e6ab861231c15f" +
	"d5357805425d82aec1de85bf6d3e30fce205e3e3b8b795bbe52e40a439286d22889064f4" +
	"aeeb150359b9425f1da51b3a5c939018555d13ac42c565a0603786a919328f326709dce5" +
	"2c22ad958ecb7873b9771d1148b1c4be2efe80ba868919fc9f68b6090c2f33c156d67156" +
	"e42766a50b5d51e79637b7e58af74c2a951b1e642fa7741fec982cc937de37eff59e2005" +
	"d5939bfc031589ca143e6e8ab83f40ee08cc20a6b4a95a318352c28d18528dcaf966705d" +
	"e17afa19d6e8ae91ddf33179d16ebb6ac2c69cae8373d408ebf8c55308be6c04d93a2543" +
	"9a94299a65a709756c7a3e568be049d5c38839"

const ocspMultiResponseHex = "30820ee60a0100a0820edf30820edb06092b060105050730010104820ecc30820ec83082" +
	"0839a216041445ac2ecd75f53f1cf6e4c51d3de0047ad0aa7465180f3230313530363032" +
	"3130303033305a3082080c3065303d300906052b0e03021a05000414f7452a0080601527" +
	"72e4a135e76e9e52fde0f1580414edd8f2ee977252853a330b297a18f5c993853b3f0204" +
	"5456656a8000180f32303135303630323039303230375aa011180f323031353036303331" +
	"30303033305a3065303d300906052b0e03021a05000414f7452a008060152772e4a135e7" +
	"6e9e52fde0f1580414edd8f2ee977252853a330b297a18f5c993853b3f02045456656b80" +
	"00180f32303135303630323039303230375aa011180f3230313530363033313030303330" +
	"5a3065303d300906052b0e03021a05000414f7452a008060152772e4a135e76e9e52fde0" +
	"f1580414edd8f2ee977252853a330b297a18f5c993853b3f02045456656c8000180f3230" +
	"3135303630323039303230375aa011180f32303135303630333130303033305a3065303d" +
	"300906052b0e03021a05000414f7452a008060152772e4a135e76e9e52fde0f1580414ed" +
	"d8f2ee977252853a330b297a18f5c993853b3f02045456656d8000180f32303135303630" +
	"323039303230375aa011180f32303135303630333130303033305a3065303d300906052b" +
	"0e03021a05000414f7452a008060152772e4a135e76e9e52fde0f1580414edd8f2ee9772" +
	"52853a330b297a18f5c993853b3f02045456656e8000180f323031353036303230393032" +
	"30375aa011180f32303135303630333130303033305a3065303d300906052b0e03021a05" +
	"000414f7452a008060152772e4a135e76e9e52fde0f1580414edd8f2ee977252853a330b" +
	"297a18f5c993853b3f02045456656f8000180f32303135303630323039303230375aa011" +
	"180f32303135303630333130303033305a3065303d300906052b0e03021a05000414f745" +
	"2a008060152772e4a135e76e9e52fde0f1580414edd8f2ee977252853a330b297a18f5c9" +
	"93853b3f0204545665708000180f32303135303630323039303230375aa011180f323031" +
	"35303630333130303033305a3065303d300906052b0e03021a05000414f7452a00806015" +
	"2772e4a135e76e9e52fde0f1580414edd8f2ee977252853a330b297a18f5c993853b3f02" +
	"04545665718000180f32303135303630323039303230375aa011180f3230313530363033" +
	"3130303033305a3065303d300906052b0e03021a05000414f7452a008060152772e4a135" +
	"e76e9e52fde0f1580414edd8f2ee977252853a330b297a18f5c993853b3f020454566572" +
	"8000180f32303135303630323039303230375aa011180f32303135303630333130303033" +
	"305a3065303d300906052b0e03021a05000414f7452a008060152772e4a135e76e9e52fd" +
	"e0f1580414edd8f2ee977252853a330b297a18f5c993853b3f0204545665738000180f32" +
	"303135303630323039303230375aa011180f32303135303630333130303033305a306530" +
	"3d300906052b0e03021a05000414f7452a008060152772e4a135e76e9e52fde0f1580414" +
	"edd8f2ee977252853a330b297a18f5c993853b3f0204545665748000180f323031353036" +
	"30323039303230375aa011180f32303135303630333130303033305a3065303d30090605" +
	"2b0e03021a05000414f7452a008060152772e4a135e76e9e52fde0f1580414edd8f2ee97" +
	"7252853a330b297a18f5c993853b3f0204545665758000180f3230313530363032303930" +
	"3230375aa011180f32303135303630333130303033305a3065303d300906052b0e03021a" +
	"05000414f7452a008060152772e4a135e76e9e52fde0f1580414edd8f2ee977252853a33" +
	"0b297a18f5c993853b3f0204545665768000180f32303135303630323039303230375aa0" +
	"11180f32303135303630333130303033305a3065303d300906052b0e03021a05000414f7" +
	"452a008060152772e4a135e76e9e52fde0f1580414edd8f2ee977252853a330b297a18f5" +
	"c993853b3f0204545665778000180f32303135303630323039303230375aa011180f3230" +
	"3135303630333130303033305a3065303d300906052b0e03021a05000414f7452a008060" +
	"152772e4a135e76e9e52fde0f1580414edd8f2ee977252853a330b297a18f5c993853b3f" +
	"0204545665788000180f32303135303630323039303230375aa011180f32303135303630" +
	"333130303033305a3065303d300906052b0e03021a05000414f7452a008060152772e4a1" +
	"35e76e9e52fde0f1580414edd8f2ee977252853a330b297a18f5c993853b3f0204545665" +
	"798000180f32303135303630323039303230375aa011180f323031353036303331303030" +
	"33305a3065303d300906052b0e03021a05000414f7452a008060152772e4a135e76e9e52" +
	"fde0f1580414edd8f2ee977252853a330b297a18f5c993853b3f02045456657a8000180f" +
	"32303135303630323039303230375aa011180f32303135303630333130303033305a3065" +
	"303d300906052b0e03021a05000414f7452a008060152772e4a135e76e9e52fde0f15804" +
	"14edd8f2ee977252853a330b297a18f5c993853b3f02045456657b8000180f3230313530" +
	"3630323039303230375aa011180f32303135303630333130303033305a3065303d300906" +
	"052b0e03021a05000414f7452a008060152772e4a135e76e9e52fde0f1580414edd8f2ee" +
	"977252853a330b297a18f5c993853b3f02045456657c8000180f32303135303630323039" +
	"303230375aa011180f32303135303630333130303033305a3065303d300906052b0e0302" +
	"1a05000414f7452a008060152772e4a135e76e9e52fde0f1580414edd8f2ee977252853a" +
	"330b297a18f5c993853b3f02045456657d8000180f32303135303630323039303230375a" +
	"a011180f32303135303630333130303033305a300d06092a864886f70d01010505000382" +
	"01010016b73b92859979f27d15eb018cf069eed39c3d280213565f3026de11ba15bdb94d" +
	"764cf2d0fdd204ef926c588d7b183483c8a2b1995079c7ed04dcefcc650c1965be4b6832" +
	"a8839e832f7f60f638425eccdf9bc3a81fbe700fda426ddf4f06c29bee431bbbe81effda" +
	"a60b7da5b378f199af2f3c8380be7ba6c21c8e27124f8a4d8989926aea19055700848d33" +
	"799e833512945fd75364edbd2dd18b783c1e96e332266b17979a0b88c35b43f47c87c493" +
	"19155056ad8dbbae5ff2afad3c0e1c69ed111206ffda49875e8e4efc0926264823bc4423" +
	"c8a002f34288c4bc22516f98f54fc609943721f590ddd8d24f989457526b599b0eb75cb5" +
	"a80da1ad93a621a08205733082056f3082056b30820453a0030201020204545638c4300d" +
	"06092a864886f70d01010b0500308182310b300906035504061302555331183016060355" +
	"040a130f552e532e20476f7665726e6d656e7431233021060355040b131a446570617274" +
	"6d656e74206f662074686520547265617375727931223020060355040b13194365727469" +
	"6669636174696f6e20417574686f7269746965733110300e060355040b13074f43494f20" +
	"4341301e170d3135303332303131353531335a170d3135303633303034303030305a3081" +
	"98310b300906035504061302555331183016060355040a130f552e532e20476f7665726e" +
	"6d656e7431233021060355040b131a4465706172746d656e74206f662074686520547265" +
	"617375727931223020060355040b131943657274696669636174696f6e20417574686f72" +
	"69746965733110300e060355040b13074f43494f204341311430120603550403130b4f43" +
	"5350205369676e657230820122300d06092a864886f70d01010105000382010f00308201" +
	"0a0282010100c1b6fe1ba1ad50bb98c855811acbd67fe68057f48b8e08d3800e7f2c51b7" +
	"9e20551934971fd92b9c9e6c49453097927cba83a94c0b2fea7124ba5ac442b38e37dba6" +
	"7303d4962dd7d92b22a04b0e0e182e9ea67620b1c6ce09ee607c19e0e6e3adae81151db1" +
	"2bb7f706149349a292e21c1eb28565b6839df055e1a838a772ff34b5a1452618e2c26042" +
	"705d53f0af4b57aae6163f58216af12f3887813fe44b0321827b3a0c52b0e47d0aab94a2" +
	"f768ab0ba3901d22f8bb263823090b0e37a7f8856db4b0d165c42f3aa7e94f5f6ce1855e" +
	"98dc57adea0ae98ad39f67ecdec00b88685566e9e8d69f6cefb6ddced53015d0d3b862bc" +
	"be21f3d72251eefcec730203010001a38201cf308201cb300e0603551d0f0101ff040403" +
	"020780306b0603551d2004643062300c060a60864801650302010502300c060a60864801" +
	"650302010503300c060a60864801650302010504300c060a60864801650302010507300c" +
	"060a60864801650302010508300c060a6086480165030201030d300c060a608648016503" +
	"020103113081e506082b060105050701010481d83081d5303006082b0601050507300286" +
	"24687474703a2f2f706b692e74726561732e676f762f746f63615f65655f6169612e7037" +
	"633081a006082b060105050730028681936c6461703a2f2f6c6461702e74726561732e67" +
	"6f762f6f753d4f43494f25323043412c6f753d43657274696669636174696f6e25323041" +
	"7574686f7269746965732c6f753d4465706172746d656e742532306f6625323074686525" +
	"323054726561737572792c6f3d552e532e253230476f7665726e6d656e742c633d55533f" +
	"634143657274696669636174653b62696e61727930130603551d25040c300a06082b0601" +
	"0505070309300f06092b060105050730010504020500301f0603551d23041830168014a2" +
	"13a8e5c607546c243d4eb72b27a2a7711ab5af301d0603551d0e0416041451f98046818a" +
	"e46d953ac90c210ccfaa1a06980c300d06092a864886f70d01010b050003820101003a37" +
	"0b301d14ffdeb370883639bec5ae6f572dcbddadd672af16ee2a8303316b14e1fbdca8c2" +
	"8f4bad9c7b1410250e149c14e9830ca6f17370a8d13151205d956e28c141cc0500379596" +
	"c5b9239fcfa3d2de8f1d4f1a2b1bf2d1851bed1c86012ee8135bdc395cd4496ce69fadd0" +
	"3b682b90350ca7b4f458190b7a0ab5c33a04cf1347a77d541877a380a4c94988c5658908" +
	"44fdc22637a72b9fa410333e2caf969477f9fe07f50e3681c204fb3bf073b9da01cd8d91" +
	"8044c40b1159955af12a3263ab1d34119d7f59bfa6cae88ed058addc4e08250263f8f836" +
	"2f5bdffd45636fea7474c60a55c535954477b2f286e1b2535f0dd12c162f1b353c370e08" +
	"be67"

const ocspMultiResponseCertHex = "308207943082067ca003020102020454566573300d06092a864886f70d01010b05003081" +
	"82310b300906035504061302555331183016060355040a130f552e532e20476f7665726e" +
	"6d656e7431233021060355040b131a4465706172746d656e74206f662074686520547265" +
	"617375727931223020060355040b131943657274696669636174696f6e20417574686f72" +
	"69746965733110300e060355040b13074f43494f204341301e170d313530343130313535" +
	"3733385a170d3138303431303136323733385a30819d310b300906035504061302555331" +
	"183016060355040a130f552e532e20476f7665726e6d656e7431233021060355040b131a" +
	"4465706172746d656e74206f662074686520547265617375727931253023060355040b13" +
	"1c427572656175206f66207468652046697363616c20536572766963653110300e060355" +
	"040b130744657669636573311630140603550403130d706b692e74726561732e676f7630" +
	"820122300d06092a864886f70d01010105000382010f003082010a0282010100c7273623" +
	"8c49c48bf501515a2490ef6e5ae0c06e0ad2aa9a6bb77f3d0370d846b2571581ebf38fd3" +
	"1948daad3dec7a4da095f1dcbe9654e65bcf7acdfd4ee802421dad9b90536c721d2bca58" +
	"8413e6bfd739a72470560bb7d64f9a09284f90ff8af1d5a3c5c84d0f95a00f9c6d988dd0" +
	"d87f1d0d3344580901c955139f54d09de0acdbd3322b758cb0c58881bf04913243401f44" +
	"013fd9f6d8348044cc8bb0a71978ad93366b2a4687a5274b2ee07d0fb40225453eb244ed" +
	"b20152251ac77c59455260ff07eeceb3cb3c60fb8121cf92afd3daa2a4650e1942ccb555" +
	"de10b3d481feb299838ef05d0fd1810b146753472ae80da65dd34da25ca1f89971f10039" +
	"0203010001a38203f3308203ef300e0603551d0f0101ff0404030205a030170603551d20" +
	"0410300e300c060a60864801650302010503301106096086480186f84201010404030206" +
	"4030130603551d25040c300a06082b060105050703013082010806082b06010505070101" +
	"0481fb3081f8303006082b060105050730028624687474703a2f2f706b692e7472656173" +
	"2e676f762f746f63615f65655f6169612e7037633081a006082b06010505073002868193" +
	"6c6461703a2f2f6c6461702e74726561732e676f762f6f753d4f43494f25323043412c6f" +
	"753d43657274696669636174696f6e253230417574686f7269746965732c6f753d446570" +
	"6172746d656e742532306f6625323074686525323054726561737572792c6f3d552e532e" +
	"253230476f7665726e6d656e742c633d55533f634143657274696669636174653b62696e" +
	"617279302106082b060105050730018615687474703a2f2f6f6373702e74726561732e67" +
	"6f76307b0603551d1104743072811c6373612d7465616d4066697363616c2e7472656173" +
	"7572792e676f768210706b692e74726561737572792e676f768210706b692e64696d632e" +
	"6468732e676f76820d706b692e74726561732e676f76811f6563622d686f7374696e6740" +
	"66697363616c2e74726561737572792e676f76308201890603551d1f048201803082017c" +
	"3027a025a0238621687474703a2f2f706b692e74726561732e676f762f4f43494f5f4341" +
	"332e63726c3082014fa082014ba0820147a48197308194310b3009060355040613025553" +
	"31183016060355040a130f552e532e20476f7665726e6d656e7431233021060355040b13" +
	"1a4465706172746d656e74206f662074686520547265617375727931223020060355040b" +
	"131943657274696669636174696f6e20417574686f7269746965733110300e060355040b" +
	"13074f43494f2043413110300e0603550403130743524c313430398681aa6c6461703a2f" +
	"2f6c6461702e74726561732e676f762f636e3d43524c313430392c6f753d4f43494f2532" +
	"3043412c6f753d43657274696669636174696f6e253230417574686f7269746965732c6f" +
	"753d4465706172746d656e742532306f6625323074686525323054726561737572792c6f" +
	"3d552e532e253230476f7665726e6d656e742c633d55533f636572746966696361746552" +
	"65766f636174696f6e4c6973743b62696e617279302b0603551d1004243022800f323031" +
	"35303431303135353733385a810f32303138303431303136323733385a301f0603551d23" +
	"041830168014a213a8e5c607546c243d4eb72b27a2a7711ab5af301d0603551d0e041604" +
	"14b0869c12c293914cd460e33ed43e6c5a26e0d68f301906092a864886f67d074100040c" +
	"300a1b0456382e31030203a8300d06092a864886f70d01010b050003820101004968d182" +
	"8f9efdc147e747bb5dda15536a42a079b32d3d7f87e619b483aeee70b7e26bda393c6028" +
	"7c733ecb468fe8b8b11bf809ff76add6b90eb25ad8d3a1052e43ee281e48a3a1ebe7efb5" +
	"9e2c4a48765dedeb23f5346242145786cc988c762d230d28dd33bf4c2405d80cbb2cb1d6" +
	"4c8f10ba130d50cb174f6ffb9cfc12808297a2cefba385f4fad170f39b51ebd87c12abf9" +
	"3c51fc000af90d8aaba78f48923908804a5eb35f617ccf71d201e3708a559e6d16f9f13e" +
	"074361eb9007e28d86bb4e0bfa13aad0e9ddd9124e84519de60e2fc6040b18d9fd602b02" +
	"684b4c071c3019fc842197d00c120c41654bcbfbc4a096a1c637b79112b81ce1fa3899f9"

const ocspRequestHex = "3051304f304d304b3049300906052b0e03021a05000414c0fe0278fc99188891b3f212e9" +
	"c7e1b21ab7bfc004140dfc1df0a9e0f01ce7f2b213177e6f8d157cd4f60210017f77deb3" +
	"bcbb235d44ccc7dba62e72"

const leafCertHex = "308203c830820331a0030201020210017f77deb3bcbb235d44ccc7dba62e72300d06092a" +
	"864886f70d01010505003081ba311f301d060355040a1316566572695369676e20547275" +
	"7374204e6574776f726b31173015060355040b130e566572695369676e2c20496e632e31" +
	"333031060355040b132a566572695369676e20496e7465726e6174696f6e616c20536572" +
	"766572204341202d20436c617373203331493047060355040b13407777772e7665726973" +
	"69676e2e636f6d2f43505320496e636f72702e6279205265662e204c494142494c495459" +
	"204c54442e286329393720566572695369676e301e170d3132303632313030303030305a" +
	"170d3133313233313233353935395a3068310b3009060355040613025553311330110603" +
	"550408130a43616c69666f726e6961311230100603550407130950616c6f20416c746f31" +
	"173015060355040a130e46616365626f6f6b2c20496e632e311730150603550403140e2a" +
	"2e66616365626f6f6b2e636f6d30819f300d06092a864886f70d010101050003818d0030" +
	"818902818100ae94b171e2deccc1693e051063240102e0689ae83c39b6b3e74b97d48d7b" +
	"23689100b0b496ee62f0e6d356bcf4aa0f50643402f5d1766aa972835a7564723f39bbef" +
	"5290ded9bcdbf9d3d55dfad23aa03dc604c54d29cf1d4b3bdbd1a809cfae47b44c7eae17" +
	"c5109bee24a9cf4a8d911bb0fd0415ae4c3f430aa12a557e2ae10203010001a382011e30" +
	"82011a30090603551d130402300030440603551d20043d303b3039060b6086480186f845" +
	"01071703302a302806082b06010505070201161c68747470733a2f2f7777772e76657269" +
	"7369676e2e636f6d2f727061303c0603551d1f043530333031a02fa02d862b687474703a" +
	"2f2f535652496e746c2d63726c2e766572697369676e2e636f6d2f535652496e746c2e63" +
	"726c301d0603551d250416301406082b0601050507030106082b06010505070302300b06" +
	"03551d0f0404030205a0303406082b0601050507010104283026302406082b0601050507" +
	"30018618687474703a2f2f6f6373702e766572697369676e2e636f6d30270603551d1104" +
	"20301e820e2a2e66616365626f6f6b2e636f6d820c66616365626f6f6b2e636f6d300d06" +
	"092a864886f70d0101050500038181005b6c2b75f8ed30aa51aad36aba595e555141951f" +
	"81a53b447910ac1f76ff78fc2781616b58f3122afc1c87010425e9ed43df1a7ba6498060" +
	"67e2688af03db58c7df4ee03309a6afc247ccb134dc33e54c6bc1d5133a532a73273b1d7" +
	"9cadc08e7e1a83116d34523340b0305427a21742827c98916698ee7eaf8c3bdd71700817"

const issuerCertHex = "30820383308202eca003020102021046fcebbab4d02f0f926098233f93078f300d06092a" +
	"864886f70d0101050500305f310b300906035504061302555331173015060355040a130e" +
	"566572695369676e2c20496e632e31373035060355040b132e436c617373203320507562" +
	"6c6963205072696d6172792043657274696669636174696f6e20417574686f7269747930" +
	"1e170d3937303431373030303030305a170d3136313032343233353935395a3081ba311f" +
	"301d060355040a1316566572695369676e205472757374204e6574776f726b3117301506" +
	"0355040b130e566572695369676e2c20496e632e31333031060355040b132a5665726953" +
	"69676e20496e7465726e6174696f6e616c20536572766572204341202d20436c61737320" +
	"3331493047060355040b13407777772e766572697369676e2e636f6d2f43505320496e63" +
	"6f72702e6279205265662e204c494142494c495459204c54442e28632939372056657269" +
	"5369676e30819f300d06092a864886f70d010101050003818d0030818902818100d88280" +
	"e8d619027d1f85183925a2652be1bfd405d3bce6363baaf04c6c5bb6e7aa3c734555b2f1" +
	"bdea9742ed9a340a15d4a95cf54025ddd907c132b2756cc4cabba3fe56277143aa63f530" +
	"3e9328e5faf1093bf3b74d4e39f75c495ab8c11dd3b28afe70309542cbfe2b518b5a3c3a" +
	"f9224f90b202a7539c4f34e7ab04b27b6f0203010001a381e33081e0300f0603551d1304" +
	"0830060101ff02010030440603551d20043d303b3039060b6086480186f8450107010130" +
	"2a302806082b06010505070201161c68747470733a2f2f7777772e766572697369676e2e" +
	"636f6d2f43505330340603551d25042d302b06082b0601050507030106082b0601050507" +
	"030206096086480186f8420401060a6086480186f845010801300b0603551d0f04040302" +
	"0106301106096086480186f842010104040302010630310603551d1f042a30283026a024" +
	"a0228620687474703a2f2f63726c2e766572697369676e2e636f6d2f706361332e63726c" +
	"300d06092a864886f70d010105050003818100408e4997968a73dd8e4def3e61b7caa062" +
	"adf40e0abb753de26ed82cc7bff4b98c369bcaa2d09c724639f6a682036511c4bcbf2da6" +
	"f5d93b0ab598fab378b91ef22b4c62d5fdb27a1ddf33fd73f9a5d82d8c2aead1fcb028b6" +
	"e94948134b838a1b487b24f738de6f4154b8ab576b06dfc7a2d4a9f6f136628088f28b75" +
	"d68071"

// Key and certificate for the OCSP responder were not taken from the Thawte
// responder, since CreateResponse requires that we have the private key.
// Instead, they were generated randomly.
const responderPrivateKeyHex = "308204a40201000282010100e8155f2d3e6f2e8d14c62a788bd462f9f844e7a6977c83ef" +
	"1099f0f6616ec5265b56f356e62c5400f0b06a2e7945a82752c636df32a895152d6074df" +
	"1701dc6ccfbcbec75a70bd2b55ae2be7e6cad3b5fd4cd5b7790ab401a436d3f5f346074f" +
	"fde8a99d5b723350f0a112076614b12ef79c78991b119453445acf2416ab0046b540db14" +
	"c9fc0f27b8989ad0f63aa4b8aefc91aa8a72160c36307c60fec78a93d3fddf4259902aa7" +
	"7e7332971c7d285b6a04f648993c6922a3e9da9adf5f81508c3228791843e5d49f24db2f" +
	"1290bafd97e655b1049a199f652cd603c4fafa330c390b0da78fbbc67e8fa021cbd74eb9" +
	"6222b12ace31a77dcf920334dc94581b02030100010282010100bcf0b93d7238bda329a8" +
	"72e7149f61bcb37c154330ccb3f42a85c9002c2e2bdea039d77d8581cd19bed94078794e" +
	"56293d601547fc4bf6a2f9002fe5772b92b21b254403b403585e3130cc99ccf08f0ef81a" +
	"575b38f597ba4660448b54f44bfbb97072b5a2bf043bfeca828cf7741d13698e3f38162b" +
	"679faa646b82abd9a72c5c7d722c5fc577a76d2c2daac588accad18516d1bbad10b0dfa2" +
	"05cfe246b59e28608a43942e1b71b0c80498075121de5b900d727c31c42c78cf1db5c0aa" +
	"5b491e10ea4ed5c0962aaf2ae025dd81fa4ce490d9d6b4a4465411d8e542fc88617e5695" +
	"1aa4fc8ea166f2b4d0eb89ef17f2b206bd5f1014bf8fe0e71fe62f2cccf102818100f2dc" +
	"ddf878d553286daad68bac4070a82ffec3dc4666a2750f47879eec913f91836f1d976b60" +
	"daf9356e078446dafab5bd2e489e5d64f8572ba24a4ba4f3729b5e106c4dd831cc2497a7" +
	"e6c7507df05cb64aeb1bbc81c1e340d58b5964cf39cff84ea30c29ec5d3f005ee1362698" +
	"07395037955955655292c3e85f6187fa1f9502818100f4a33c102630840705f8c778a47b" +
	"87e8da31e68809af981ac5e5999cf1551685d761cdf0d6520361b99aebd5777a940fa64d" +
	"327c09fa63746fbb3247ec73a86edf115f1fe5c83598db803881ade71c33c6e956118345" +
	"497b98b5e07bb5be75971465ec78f2f9467e1b74956ca9d4c7c3e314e742a72d8b33889c" +
	"6c093a466cef0281801d3df0d02124766dd0be98349b19eb36a508c4e679e793ba0a8bef" +
	"4d786888c1e9947078b1ea28938716677b4ad8c5052af12eb73ac194915264a913709a0b" +
	"7b9f98d4a18edd781a13d49899f91c20dbd8eb2e61d991ba19b5cdc08893f5cb9d39e5a6" +
	"0629ea16d426244673b1b3ee72bd30e41fac8395acac40077403de5efd028180050731dd" +
	"d71b1a2b96c8d538ba90bb6b62c8b1c74c03aae9a9f59d21a7a82b0d572ef06fa9c807bf" +
	"c373d6b30d809c7871df96510c577421d9860c7383fda0919ece19996b3ca13562159193" +
	"c0c246471e287f975e8e57034e5136aaf44254e2650def3d51292474c515b1588969112e" +
	"0a85cc77073e9d64d2c2fc497844284b02818100d71d63eabf416cf677401ebf965f8314" +
	"120b568a57dd3bd9116c629c40dc0c6948bab3a13cc544c31c7da40e76132ef5dd3f7534" +
	"45a635930c74326ae3df0edd1bfb1523e3aa259873ac7cf1ac31151ec8f37b528c275622" +
	"48f99b8bed59fd4da2576aa6ee20d93a684900bf907e80c66d6e2261ae15e55284b4ed9d" +
	"6bdaa059"

const responderCertHex = "308202e2308201caa003020102020101300d06092a864886f70d01010b05003019311730" +
	"150603550403130e4f43535020526573706f6e646572301e170d31353031333031353530" +
	"33335a170d3136303133303135353033335a3019311730150603550403130e4f43535020" +
	"526573706f6e64657230820122300d06092a864886f70d01010105000382010f00308201" +
	"0a0282010100e8155f2d3e6f2e8d14c62a788bd462f9f844e7a6977c83ef1099f0f6616e" +
	"c5265b56f356e62c5400f0b06a2e7945a82752c636df32a895152d6074df1701dc6ccfbc" +
	"bec75a70bd2b55ae2be7e6cad3b5fd4cd5b7790ab401a436d3f5f346074ffde8a99d5b72" +
	"3350f0a112076614b12ef79c78991b119453445acf2416ab0046b540db14c9fc0f27b898" +
	"9ad0f63aa4b8aefc91aa8a72160c36307c60fec78a93d3fddf4259902aa77e7332971c7d" +
	"285b6a04f648993c6922a3e9da9adf5f81508c3228791843e5d49f24db2f1290bafd97e6" +
	"55b1049a199f652cd603c4fafa330c390b0da78fbbc67e8fa021cbd74eb96222b12ace31" +
	"a77dcf920334dc94581b0203010001a3353033300e0603551d0f0101ff04040302078030" +
	"130603551d25040c300a06082b06010505070309300c0603551d130101ff04023000300d" +
	"06092a864886f70d01010b05000382010100718012761b5063e18f0dc44644d8e6ab8612" +
	"31c15fd5357805425d82aec1de85bf6d3e30fce205e3e3b8b795bbe52e40a439286d2288" +
	"9064f4aeeb150359b9425f1da51b3a5c939018555d13ac42c565a0603786a919328f3267" +
	"09dce52c22ad958ecb7873b9771d1148b1c4be2efe80ba868919fc9f68b6090c2f33c156" +
	"d67156e42766a50b5d51e79637b7e58af74c2a951b1e642fa7741fec982cc937de37eff5" +
	"9e2005d5939bfc031589ca143e6e8ab83f40ee08cc20a6b4a95a318352c28d18528dcaf9" +
	"66705de17afa19d6e8ae91ddf33179d16ebb6ac2c69cae8373d408ebf8c55308be6c04d9" +
	"3a25439a94299a65a709756c7a3e568be049d5c38839"

const errorResponseHex = "30030a0101"

func fromHex(h string) []byte {
	data, _ := hex.DecodeString(h)
	return data
}
