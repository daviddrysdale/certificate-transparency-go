package x509

import "fmt"

// To preserve error IDs, only append to this list, never insert.
const (
	ErrInvalidID ErrorID = iota
	errAsn1InvalidPubKeyRsa
	errAsn1InvalidPubKeyRsaLax
	errAsn1TrailingPubKeyRsa
	errPubKeyRsaNegModulus
	errPubKeyRsaNegExponent
	errPubKeyRsaMissingParams
	errAsn1InvalidPubKeyDsa
	errAsn1InvalidPubKeyDsaLax
	errAsn1TrailingPubKeyDsa
	errAsn1InvalidPubKeyDsaParams
	errAsn1TrailingPubKeyDsaParams
	errPubKeyDsaNegParam
	errAsn1InvalidPubKeyEcdsa
	errAsn1InvalidPubKeyEcdsaLax
	errAsn1TrailingPubKeyEcdsa
	errPubKeyEcdsaUnsupportedCurve
	errAsn1InvalidPubKeyEcdsaCurvePt
	errPubKeyUnsupportedAlgorithm
	errAsn1InvalidGeneralName
	errAsn1InvalidGeneralNameOther
	errAsn1InvalidGeneralNameDirName
	errGeneralNameIPMaskLen
	errGeneralNameIPLen
	errAsn1InvalidGeneralNameOID
	errAsn1InvalidAltName
	errAsn1TrailingAltName
	errInvalidAltNameTag
	errSignatureAlgorithmUnknown
	errPublicKeyAlgorithmUnknown
	errSerialNumberNegative
	errSerialNumberZero
	errAsn1InvalidSubject
	errAsn1InvalidSubjectLax
	errAsn1TrailingSubject
	errAsn1InvalidIssuer
	errAsn1InvalidIssuerLax
	errAsn1TrailingIssuer
	errAsn1InvalidKeyUsage
	errAsn1InvalidKeyUsageTrailingZeros
	errAsn1TrailingKeyUsage
	errAsn1InvalidBasicConstraints
	errAsn1TrailingBasicConstraints
	errAsn1InvalidNameConstraints
	errAsn1TrailingNameConstraints
	errNameConstraintsExcludedMinMax
	errAsn1TrailingNameConstraintsExcluded
	errNameConstraintsPermittedMinMax
	errAsn1TrailingNameConstraintsPermitted
	errAsn1InvalidCRLDistributionPoints
	errAsn1TrailingCRLDistributionPoints
	errAsn1InvalidCRLDistributionPointName
	errAsn1InvalidFreshestCRL
	errAsn1TrailingFreshestCRL
	errAsn1InvalidFreshestCRLName
	errAsn1InvalidAuthorityKeyID
	errAsn1TrailingAuthorityKeyID
	errAsn1InvalidExtKeyUsage
	errAsn1TrailingExtKeyUsage
	errAsn1InvalidSubjectKeyID
	errAsn1TrailingSubjectKeyID
	errAsn1InvalidCertificatePolicies
	errAsn1TrailingCertificatePolicies
	errAsn1InvalidInfoAccess
	errAsn1TrailingInfoAccess
	errAsn1InvalidCertificate
	errAsn1CertificateLaxDecodingRequired
	errAsn1TrailingCertificate
	errCriticalExtensionUnhandled
	errAsn1InvalidInhibitAnyPolicy
	errAsn1TrailingInhibitAnyPolicy
	errInhibitAnyPolicyNegSkip
	errAsn1InvalidPolicyMappings
	errAsn1TrailingPolicyMappings
	errAsn1InvalidPolicyConstraints
	errAsn1TrailingPolicyConstraints
	errUnexpectedlyCriticalExtension
	errUnexpectedlyNonCriticalExtension
	errDuplicateExtension
	errKeyUsageEmpty
	errKeyUsageWrongBitCount
	errKeyUsageCANoSign
	errKeyUsageNonCAKeySign
	errExtensionsInOldCert
	errUniqueIDInV1Cert
	errUniqueIDNoExtsNotV2
	errNameConstraintsEmpty
	errNameConstraintsNonCA
	errNameConstraintsRegisteredID
	errPolicyConstraintsEmpty
	errPolicyMappingsEmpty
	errPolicyMappingsAnyPolicy
	errPolicyMappingsMissingPolicy
	errCertificatePoliciesDuplicate
	errBasicConstraintsNegativePathLen
	errAltNameBlankDNS
	errSubjectKeyIDMissingInCA
	errAuthorityInformationAccessEmpty
	errSubjectInformationAccessEmpty
	errAuthorityKeyIDEmpty
	errCertificatePoliciesQualifiers
	errCertificatePoliciesQualifierUnknown
	errCertificatePoliciesQualifierUnknownAny
	errBasicConstraintsCANonCritical
	errPublicKeyAlgorithmObsoleteOID
	errAsn1InvalidValidity
	errAsn1TrailingValidity
	errAsn1InvalidValidityTag
	errDateLateForUTC
	errDateEarlyForGeneralized
	errDateNonZulu
	errDateIncomplete
	errDateFraction
	errAsn1InvalidSubjectDirAttrs
	errAsn1TrailingSubjectDirAttrs
	errSubjectDirAttrsEmpty
	// ErrCTPoisonExtensionPresent should only occur for Certificate
	// Transparency pre-certificates (which can be parsed with the
	// ParsePreCertificate entrypoint).
	ErrCTPoisonExtensionPresent
	errAsn1InvalidSCT
	errAsn1TrailingSCT
	errAsn1InvalidSCTContents
	errAsn1TrailingSCTContents
	ErrInvalidCertList
	ErrTrailingCertList
	ErrUnexpectedlyCriticalCertListExtension
	ErrUnexpectedlyNonCriticalCertListExtension
	ErrInvalidCertListAuthKeyID
	ErrTrailingCertListAuthKeyID
	ErrInvalidCertListIssuerAltName
	ErrInvalidCertListCRLNumber
	ErrTrailingCertListCRLNumber
	ErrNegativeCertListCRLNumber
	ErrInvalidCertListDeltaCRL
	ErrTrailingCertListDeltaCRL
	ErrNegativeCertListDeltaCRL
	ErrInvalidCertListIssuingDP
	ErrTrailingCertListIssuingDP
	ErrCertListIssuingDPMultipleTypes
	ErrCertListIssuingDPInvalidFullName
	ErrInvalidCertListFreshestCRL
	ErrInvalidCertListAuthInfoAccess
	ErrTrailingCertListAuthInfoAccess
	ErrUnhandledCriticalCertListExtension
	ErrUnexpectedlyCriticalRevokedCertExtension
	ErrUnexpectedlyNonCriticalRevokedCertExtension
	ErrInvalidRevocationReason
	ErrTrailingRevocationReason
	ErrInvalidRevocationInvalidityDate
	ErrTrailingRevocationInvalidityDate
	ErrInvalidRevocationIssuer
	ErrUnhandledCriticalRevokedCertExtension

	ErrMaxID
)

// idToError gives a template x509.Error for each defined ErrorID; where the Summary
// field may hold format specifiers that take field parameters.
var idToError map[ErrorID]Error

var errorInfo = []Error{
	{
		ID:       errAsn1InvalidPubKeyRsa,
		Summary:  "%v",
		Field:    "tbsCertificate.subjectPublicKeyInfo.RSAPublicKey",
		SpecRef:  "RFC 5280 s4.1.2.7",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidPubKeyRsaLax,
		Summary:  "%v",
		Field:    "tbsCertificate.subjectPublicKeyInfo.RSAPublicKey",
		SpecRef:  "RFC 5280 s4.1.2.7",
		Category: InvalidASN1Content,
	},
	{
		ID:       errAsn1TrailingPubKeyRsa,
		Summary:  "x509: trailing data after RSA public key",
		Field:    "tbsCertificate.subjectPublicKeyInfo.RSAPublicKey",
		SpecRef:  "RFC 5280 s4.1.2.7",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errPubKeyRsaNegModulus,
		Summary:  "x509: RSA modulus is not a positive number",
		Field:    "tbsCertificate.subjectPublicKeyInfo.RSAPublicKey.modulus",
		SpecRef:  "RFC 3279 s2.3.1",
		Category: MalformedCertificate,
		Fatal:    true,
	},
	{
		ID:       errPubKeyRsaNegExponent,
		Summary:  "x509: RSA public exponent is not a positive number",
		Field:    "tbsCertificate.subjectPublicKeyInfo.RSAPublicKey.publicExponent",
		SpecRef:  "RFC 3279 s2.3.1",
		Category: MalformedCertificate,
		Fatal:    true,
	},
	{
		ID:       errPubKeyRsaMissingParams,
		Summary:  "x509: RSA key missing NULL parameters",
		Field:    "tbsCertificate.subjectPublicKeyInfo.RSAPublicKey.publicExponent",
		SpecRef:  "RFC 3279 s2.2.1",
		Category: MalformedCertificate,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidPubKeyDsa,
		Summary:  "%v",
		Field:    "tbsCertificate.subjectPublicKeyInfo.Dss-Sig-Value",
		SpecRef:  "RFC 5280 s4.1.2.7",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidPubKeyDsaLax,
		Summary:  "%v",
		Field:    "tbsCertificate.subjectPublicKeyInfo.Dss-Sig-Value",
		SpecRef:  "RFC 5280 s4.1.2.7",
		Category: InvalidASN1Content,
	},
	{
		ID:       errAsn1TrailingPubKeyDsa,
		Summary:  "x509: trailing data after DSA public key",
		Field:    "tbsCertificate.subjectPublicKeyInfo.Dss-Sig-Value",
		SpecRef:  "RFC 5280 s4.1.2.7",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidPubKeyDsaParams,
		Summary:  "%v",
		Field:    "tbsCertificate.subjectPublicKeyInfo.Dss-Sig-Value",
		SpecRef:  "RFC 3279 s2.3.2",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1TrailingPubKeyDsaParams,
		Summary:  "x509: trailing data after DSA parameters",
		Field:    "tbsCertificate.subjectPublicKeyInfo.Dss-Sig-Value",
		SpecRef:  "RFC 3279 s2.3.2",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errPubKeyDsaNegParam,
		Summary:  "x509: zero or negative DSA parameter",
		Field:    "tbsCertificate.subjectPublicKeyInfo.Dss-Sig-Value",
		SpecRef:  "RFC 3279 s2.3.2",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidPubKeyEcdsa,
		Summary:  "%v",
		Field:    "tbsCertificate.subjectPublicKeyInfo.EcpkParameters",
		SpecRef:  "RFC 5280 s4.1.2.7",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidPubKeyEcdsaLax,
		Summary:  "%v",
		Field:    "tbsCertificate.subjectPublicKeyInfo.EcpkParameters",
		SpecRef:  "RFC 5280 s4.1.2.7",
		Category: InvalidASN1Content,
	},
	{
		ID:       errAsn1TrailingPubKeyEcdsa,
		Summary:  "x509: trailing data after ECDSA parameters",
		Field:    "tbsCertificate.subjectPublicKeyInfo.EcpkParameters",
		SpecRef:  "RFC 5280 s4.1.2.7",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errPubKeyEcdsaUnsupportedCurve,
		Summary:  "x509: unsupported elliptic curve %v",
		Field:    "tbsCertificate.subjectPublicKeyInfo.EcpkParameters",
		SpecRef:  "RFC 3279 s2.3.5",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidPubKeyEcdsaCurvePt,
		Summary:  "x509: failed to unmarshal elliptic curve point",
		Field:    "tbsCertificate.subjectPublicKeyInfo.EcpkParameters",
		SpecRef:  "RFC 3279 s2.3.5",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errPubKeyUnsupportedAlgorithm,
		Summary:  "x509: unrecognized public key algorithm %v",
		Field:    "tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm",
		SpecRef:  "RFC 5280 s4.1.2.7",
		Category: UnrecognizedValue,
	},
	{
		ID:       errAsn1InvalidGeneralName,
		Summary:  "%v",
		Field:    "GeneralName",
		SpecRef:  "RFC 5280 s4.2.1.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidGeneralNameOther,
		Summary:  "%v",
		Field:    "GeneralName.otherName",
		SpecRef:  "RFC 5280 s4.1.2.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidGeneralNameDirName,
		Summary:  "%v",
		Field:    "GeneralName.directoryName",
		SpecRef:  "RFC 5280 s4.1.2.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errGeneralNameIPMaskLen,
		Summary:  "x509: certificate contains IP/mask address of length %d : %v",
		SpecRef:  "RFC5280 s4.2.1.10",
		SpecText: "For IPv4 addresses, the iPAddress field of GeneralName MUST contain eight (8) octets...For IPv6 addresses, the iPAddress field MUST contain 32 octets",
		Category: MalformedCertificate,
	},
	{
		ID:       errGeneralNameIPLen,
		Summary:  "x509: certificate contains IP address of length %d : %v",
		SpecRef:  "RFC5280 s4.2.1.6",
		SpecText: "For IP version 4, as specified in [RFC791], the octet string MUST contain exactly four octets.  For IP version 6, as specified in [RFC2460], the octet string MUST contain exactly sixteen octets",
		Category: MalformedCertificate,
	},
	{
		ID:       errAsn1InvalidGeneralNameOID,
		Summary:  "x509: invalid ASN.1 OBJECT-IDENTIFIER",
		Field:    "GeneralName.registeredID",
		SpecRef:  "RFC 5280 s4.1.2.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidAltName,
		Summary:  "%s: %v",
		Field:    "tbsCertificate.extensions.*AltName",
		SpecRef:  "RFC 5280 s4.2.1.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1TrailingAltName,
		Summary:  "x509: trailing data after X.509 extension %sAltName",
		Field:    "tbsCertificate.extensions.*AltName",
		SpecRef:  "RFC 5280 s4.2.1.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errInvalidAltNameTag,
		Summary:  "x509: invalid ASN.1 tag %d/class %d for %sAltName",
		Field:    "tbsCertificate.extensions.*AltName",
		SpecRef:  "RFC 5280 s4.2.1.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errSignatureAlgorithmUnknown,
		Summary:  "x509: unknown signature algorithm %v",
		Field:    "tbsCertificate.signature.algorithm",
		SpecRef:  "RFC 5280 s4.1.1.2",
		Category: UnrecognizedValue,
	},
	{
		ID:       errPublicKeyAlgorithmUnknown,
		Summary:  "x509: unknown public key algorithm %v",
		Field:    "tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm",
		SpecRef:  "RFC 5280 s4.1.1.2",
		Category: UnrecognizedValue,
	},
	{
		ID:       errSerialNumberNegative,
		Summary:  "x509: negative serial number",
		Field:    "tbsCertificate.serialNumber",
		SpecRef:  "RFC 5280 s4.1.2.2",
		SpecText: "The serial number MUST be a positive integer",
		Category: MalformedCertificate,
	},
	{
		ID:       errSerialNumberZero,
		Summary:  "x509: zero serial number",
		Field:    "tbsCertificate.serialNumber",
		SpecRef:  "RFC 5280 s4.1.2.2",
		SpecText: "The serial number MUST be a positive integer",
		Category: MalformedCertificate,
	},
	{
		ID:       errAsn1InvalidSubject,
		Summary:  "%v",
		Field:    "tbsCertificate.subject",
		SpecRef:  "RFC 5280 s4.1.2.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidSubjectLax,
		Summary:  "%v",
		Field:    "tbsCertificate.subject",
		SpecRef:  "RFC 5280 s4.1.2.6",
		Category: InvalidASN1Content,
	},
	{
		ID:       errAsn1TrailingSubject,
		Summary:  "x509: trailing data after X.509 subject",
		Field:    "tbsCertificate.subject",
		SpecRef:  "RFC 5280 s4.1.2.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidIssuer,
		Summary:  "%v",
		Field:    "tbsCertificate.issuer",
		SpecRef:  "RFC 5280 s4.1.2.4",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidIssuerLax,
		Summary:  "%v",
		Field:    "tbsCertificate.issuer",
		SpecRef:  "RFC 5280 s4.1.2.4",
		Category: InvalidASN1Content,
	},
	{
		ID:       errAsn1TrailingIssuer,
		Summary:  "x509: trailing data after X.509 issuer",
		Field:    "tbsCertificate.issuer",
		SpecRef:  "RFC 5280 s4.1.2.4",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidKeyUsage,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.KeyUsage",
		SpecRef:  "RFC 5280 s4.2.1.3",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidKeyUsageTrailingZeros,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.KeyUsage",
		SpecRef:  "RFC 5280 s4.2.1.3",
		Category: InvalidASN1Content,
	},
	{
		ID:       errAsn1TrailingKeyUsage,
		Summary:  "x509: trailing data after X.509 KeyUsage",
		Field:    "tbsCertificate.extensions.KeyUsage",
		SpecRef:  "RFC 5280 s4.2.1.3",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidBasicConstraints,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.BasicConstraints",
		SpecRef:  "RFC 5280 s4.2.1.9",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1TrailingBasicConstraints,
		Summary:  "x509: trailing data after X.509 BasicConstraints",
		Field:    "tbsCertificate.extensions.BasicConstraints",
		SpecRef:  "RFC 5280 s4.2.1.9",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidNameConstraints,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.NameConstraints",
		SpecRef:  "RFC 5280 s4.2.1.10",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1TrailingNameConstraints,
		Summary:  "x509: trailing data after NameConstraints",
		Field:    "tbsCertificate.extensions.NameConstraints",
		SpecRef:  "RFC 5280 s4.2.1.10",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errNameConstraintsExcludedMinMax,
		Summary:  "x509: min/max values present in NameConstraints excludedSubtrees",
		Field:    "tbsCertificate.extensions.NameConstraints.excludedSubtrees",
		SpecRef:  "RFC 5280 s4.2.1.10",
		SpecText: "the minimum MUST be zero, and maximum MUST be absent",
		Category: MalformedCertificate,
	},
	{
		ID:       errAsn1TrailingNameConstraintsExcluded,
		Summary:  "x509: trailing data after GeneralName",
		Field:    "tbsCertificate.extensions.NameConstraints.excluded",
		SpecRef:  "RFC 5280 s4.2.1.10",
		Category: InvalidASN1Content,
	},
	{
		ID:       errNameConstraintsPermittedMinMax,
		Summary:  "x509: min/max values present in NameConstraints permittedSubtrees",
		Field:    "tbsCertificate.extensions.NameConstraints.permittedSubtrees",
		SpecRef:  "RFC 5280 s4.2.1.10",
		SpecText: "the minimum MUST be zero, and maximum MUST be absent",
		Category: MalformedCertificate,
	},
	{
		ID:       errAsn1TrailingNameConstraintsPermitted,
		Summary:  "x509: trailing data after GeneralName",
		Field:    "tbsCertificate.extensions.NameConstraints.permitted",
		SpecRef:  "RFC 5280 s4.2.1.10",
		Category: InvalidASN1Content,
	},
	{
		ID:       errAsn1InvalidCRLDistributionPoints,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.CRLDistributionPoints",
		SpecRef:  "RFC 5280 s4.2.1.13",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1TrailingCRLDistributionPoints,
		Summary:  "x509: trailing data after X.509 CRL distribution point",
		Field:    "tbsCertificate.extensions.CRLDistributionPoints",
		SpecRef:  "RFC 5280 s4.2.1.13",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidCRLDistributionPointName,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.CRLDistributionPoints",
		SpecRef:  "RFC 5280 s4.2.1.13",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidFreshestCRL,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.FreshestCRL",
		SpecRef:  "RFC 5280 s4.2.1.15",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1TrailingFreshestCRL,
		Summary:  "x509: trailing data after X.509 Freshest CRL",
		Field:    "tbsCertificate.extensions.FreshestCRL",
		SpecRef:  "RFC 5280 s4.2.1.15",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidFreshestCRLName,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.FreshestCRL",
		SpecRef:  "RFC 5280 s4.2.1.15",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidAuthorityKeyID,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.AuthorityKeyId",
		SpecRef:  "RFC 5280 s4.2.1.1",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1TrailingAuthorityKeyID,
		Summary:  "x509: trailing data after X.509 authority key-id",
		Field:    "tbsCertificate.extensions.AuthorityKeyId",
		SpecRef:  "RFC 5280 s4.2.1.1",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidExtKeyUsage,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.ExtendedKeyUsage",
		SpecRef:  "RFC 5280 s4.2.1.12",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1TrailingExtKeyUsage,
		Summary:  "x509: trailing data after X.509 ExtendedKeyUsage",
		Field:    "tbsCertificate.extensions.ExtendedKeyUsage",
		SpecRef:  "RFC 5280 s4.2.1.12",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidSubjectKeyID,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.SubjectKeyId",
		SpecRef:  "RFC 5280 s4.2.1.2",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1TrailingSubjectKeyID,
		Summary:  "x509: trailing data after X.509 key-id",
		Field:    "tbsCertificate.extensions.SubjectKeyId",
		SpecRef:  "RFC 5280 s4.2.1.2",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidCertificatePolicies,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.CertificatePolicies",
		SpecRef:  "RFC 5280 s4.2.1.4",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1TrailingCertificatePolicies,
		Summary:  "x509: trailing data after X.509 certificate policies",
		Field:    "tbsCertificate.extensions.CertificatePolicies",
		SpecRef:  "RFC 5280 s4.2.1.4",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidInfoAccess,
		Summary:  "%s: %v",
		Field:    "tbsCertificate.extensions.*InformationAccess",
		SpecRef:  "RFC 5280 s4.2.2.1",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1TrailingInfoAccess,
		Summary:  "x509: trailing data after X.509 %s information",
		Field:    "tbsCertificate.extensions.*InformationAccess",
		SpecRef:  "RFC 5280 s4.2.2.1",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidCertificate,
		Summary:  "%v",
		SpecRef:  "RFC 5280",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1CertificateLaxDecodingRequired,
		Summary:  "%v",
		SpecRef:  "RFC 5280",
		Category: InvalidASN1Content,
	},
	{
		ID:       errAsn1TrailingCertificate,
		Summary:  "Trailing ASN.1 data after certificate",
		Category: InvalidASN1Encoding,
		Fatal:    true,
	},
	{
		ID:       errCriticalExtensionUnhandled,
		Summary:  "x509: unhandled critical extension (%v)",
		Category: MalformedCertificate,
		SpecRef:  "RFC 5280 s4.2",
		SpecText: "A certificate-using system MUST reject the certificate if it encounters a critical extension it does not recognize",
	},
	{
		ID:       errAsn1InvalidInhibitAnyPolicy,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.InhibitAnyPolicy",
		SpecRef:  "RFC 5280 s4.2.1.14",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1TrailingInhibitAnyPolicy,
		Summary:  "x509: trailing data after X.509 InhibitAnyPolicy",
		Field:    "tbsCertificate.extensions.InhibitAnyPolicy",
		SpecRef:  "RFC 5280 s4.2.1.14",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errInhibitAnyPolicyNegSkip,
		Summary:  "x509: X.509 InhibitAnyPolicy with negative skip value %d",
		Field:    "tbsCertificate.extensions.InhibitAnyPolicy.SkipCerts",
		SpecRef:  "RFC 5280 s4.2.1.14",
		Category: InvalidValueRange,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidPolicyMappings,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.PolicyMappings",
		SpecRef:  "RFC 5280 s4.2.1.5",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1TrailingPolicyMappings,
		Summary:  "x509: trailing data after X.509 PolicyMappings",
		Field:    "tbsCertificate.extensions.PolicyMappings",
		SpecRef:  "RFC 5280 s4.2.1.5",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidPolicyConstraints,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.PolicyConstraints",
		SpecRef:  "RFC 5280 s4.2.1.11",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1TrailingPolicyConstraints,
		Summary:  "x509: trailing data after X.509 PolicyConstraints",
		Field:    "tbsCertificate.extensions.PolicyConstraints",
		SpecRef:  "RFC 5280 s4.2.1.11",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errUnexpectedlyCriticalExtension,
		Summary:  "x509: extension %v marked as critical but expected to be non-critical",
		Field:    "tbsCertificate.extensions.*.critical",
		SpecRef:  "RFC 5280 s4.2",
		Category: MalformedCertificate,
	},
	{
		ID:       errUnexpectedlyNonCriticalExtension,
		Summary:  "x509: extension %v marked as non-critical but expected to be critical",
		Field:    "tbsCertificate.extensions.*.critical",
		SpecRef:  "RFC 5280 s4.2",
		Category: MalformedCertificate,
	},
	{
		ID:       errDuplicateExtension,
		Summary:  "x509: extension %v occurs more than once",
		Field:    "tbsCertificate.extensions",
		SpecRef:  "RFC 5280 s4.2",
		SpecText: "A certificate MUST NOT include more than one instance of a particular extension",
		Category: MalformedCertificate,
	},
	{
		ID:       errKeyUsageEmpty,
		Summary:  "x509: KeyUsage extension with no bits set",
		Field:    "tbsCertificate.extensions.KeyUsage",
		SpecRef:  "RFC5280 s4.2.1.3",
		SpecText: "When the keyUsage extension appears in a certificate, at least one of the bits MUST be set to 1",
		Category: MalformedCertificate,
	},
	{
		ID:       errKeyUsageWrongBitCount,
		Summary:  "x509: KeyUsage extension with incorrect number of bits (%d not 9)",
		Field:    "tbsCertificate.extensions.KeyUsage",
		SpecRef:  "RFC5280 s4.2.1.3",
		SpecText: "BIT STRING {... decipherOnly (8) }",
		Category: InvalidValueRange,
	},
	{
		ID:       errKeyUsageCANoSign,
		Summary:  "x509: CA certificate missing keyCertSign bit in KeyUsage",
		Field:    "tbsCertificate.extensions.KeyUsage",
		SpecRef:  "RFC5280 s4.2.1.3",
		SpecText: "If the keyCertSign bit is asserted, then the cA bit in the basic constraints extension (Section 4.2.1.9) MUST also be asserted",
		Category: MalformedCertificate,
	},
	{
		ID:       errKeyUsageNonCAKeySign,
		Summary:  "x509: non-CA certificate with keyCertSign bit in KeyUsage",
		Field:    "tbsCertificate.extensions.KeyUsage",
		SpecRef:  "RFC5280 s4.2.1.3",
		SpecText: "If the cA boolean is not asserted, then the keyCertSign bit in the key usage extension MUST NOT be asserted.",
		Category: MalformedCertificate,
	},
	{
		ID:       errExtensionsInOldCert,
		Summary:  "x509: extensions present in non-V3 (v%d) certificate",
		Field:    "tbsCertificate.extensions",
		SpecRef:  "RFC5280 s4.1.2.9",
		SpecText: "Extensions...MUST only appear if the versions is 3",
		Category: MalformedCertificate,
	},
	{
		ID:       errUniqueIDInV1Cert,
		Summary:  "x509: SubjectUniqueIdentifier / IssuerUniqueIdentifier present in V1 cert",
		Field:    "tbsCertificate.*UniqueID",
		SpecRef:  "RFC5280 s4.1.2.8",
		SpecText: "These fields MUST NOT appear if the version is 1",
		Category: MalformedCertificate,
	},
	{
		ID:       errUniqueIDNoExtsNotV2,
		Summary:  "x509: non-V2 (V%d) certificate with UniqueIdentifier but no extensions",
		Field:    "tbsCertficiate.*UniqueID",
		SpecRef:  "RFC5280 s4.1.2.1",
		SpecText: "If no extensions are present, but a UniqueIdentifier is present, the version SHOULD be 2",
		Category: PoorlyFormedCertificate,
	},
	{
		ID:       errNameConstraintsEmpty,
		Summary:  "x509: empty NameConstraints extension",
		Field:    "tbsCertificate.extensions.NameConstraints",
		SpecRef:  "RFC5280 s4.2.1.10",
		SpecText: "Conforming CAs MUST NOT issue certificates where name constraints is an empty sequence.",
		Category: MalformedCertificate,
	},
	{
		ID:       errNameConstraintsNonCA,
		Summary:  "x509: NameConstraints extension in non-CA certificate",
		Field:    "tbsCertificate.extensions.NameConstraints",
		SpecRef:  "RFC5280 s4.2.1.10",
		SpecText: "The name constraints extension ... MUST be used only in a CA certificate",
		Category: MalformedCertificate,
	},
	{
		ID:       errNameConstraintsRegisteredID,
		Summary:  "x509: NameConstraints extension imposed constraint on %s registeredID",
		Field:    "tbsCertificate.extensions.NameConstraints.*.permittedSubtrees",
		SpecRef:  "RFC5280 s4.2.1.10",
		SpecText: "Conforming ... SHOULD NOT impose name constraints on the ... registeredID name forms",
		Category: PoorlyFormedCertificate,
	},
	{
		ID:       errPolicyConstraintsEmpty,
		Summary:  "x509: empty PolicyConstraints extension",
		Field:    "tbsCertificate.extensions.PolicyConstraints",
		SpecRef:  "RFC5280 s4.2.1.11",
		SpecText: "Conforming CAs MUST NOT issue certificates where policy constraints is an empty sequence.",
		Category: MalformedCertificate,
	},
	{
		ID:       errPolicyMappingsEmpty,
		Summary:  "x509: empty PolicyMappings extension",
		Field:    "tbsCertificate.extensions.PolicyMappings",
		SpecRef:  "RFC5280 s4.2.1.5",
		SpecText: "This extension...lists one or more pairs of OIDs",
		Category: MalformedCertificate,
	},
	{
		ID:       errPolicyMappingsAnyPolicy,
		Summary:  "x509: PolicyMappings extension %s special value anyPolicy",
		Field:    "tbsCertificate.extensions.PolicyMappings",
		SpecRef:  "RFC5280 s4.2.1.5",
		SpecText: "Policies MUST NOT be mapped either to or from the special value anyPolicy",
		Category: MalformedCertificate,
	},
	{
		ID:       errPolicyMappingsMissingPolicy,
		Summary:  "x509: PolicyMapping extension referencing unspecified policy %v",
		SpecRef:  "RFC5280 s4.2.1.5",
		SpecText: "Each issuerDomainPolicy named in the policy mappings extension SHOULD also be asserted in a certificate policies extension in the same certificate.",
		Category: PoorlyFormedCertificate,
	},
	{
		ID:       errCertificatePoliciesDuplicate,
		Summary:  "x509: duplicate policy %v in CertificatePolicies extension",
		Field:    "tbsCertificate.extensions.CertificatePolicies.policyIdentifier",
		SpecRef:  "RFC5280 s4.2.1.4",
		SpecText: "A certificate policy OID MUST NOT appear more than once in a certificate policies extension",
		Category: MalformedCertificate,
	},
	{
		ID:       errBasicConstraintsNegativePathLen,
		Summary:  "x509: BasicConstraints extension with negative path len (%d)",
		Field:    "tbsCertificate.extensions.BasicConstraints.pathLenConstraint",
		SpecRef:  "RFC5280 s4.2.1.9",
		SpecText: "Where it appears, the pathLenConstraint field MUST be greater than or equal to zero",
		Category: InvalidASN1Content,
	},
	{
		ID:       errAltNameBlankDNS,
		Summary:  "x509: altName with blank DNS name",
		Field:    "tbsCertificate.extensions.*AltName.dNSName",
		SpecRef:  "RFC5280 s4.2.1.6",
		SpecText: "subjectAltName extensions with a dNSName of ' ' MUST NOT be used",
		Category: MalformedCertificate,
	},
	{
		ID:       errSubjectKeyIDMissingInCA,
		Summary:  "x509: SubjectKeyIdentifier missing in CA certificate",
		SpecRef:  "RFC5280 s4.2.1.2",
		Field:    "tbsCertificate.extensions.SubjectKeyIdentifier",
		SpecText: "this extension MUST appear in all conforming CA certificates",
		Category: MalformedCertificate,
	},
	{
		ID:       errAuthorityInformationAccessEmpty,
		Summary:  "x509: empty AuthorityInfoAccess extension",
		Field:    "tbsCertificate.extensions.AuthorityInfoAccessSyntax",
		SpecRef:  "RFC5280 s4.2.2.2",
		SpecText: "AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription",
		Category: InvalidASN1Content,
	},
	{
		ID:       errSubjectInformationAccessEmpty,
		Summary:  "x509: empty SubjectInfoAccess extension",
		Field:    "tbsCertificate.extensions.SubjectInfoAccessSyntax",
		SpecRef:  "RFC5280 s4.2.2.2",
		SpecText: "SubjectInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription",
		Category: InvalidASN1Content,
	},
	{
		ID:       errAuthorityKeyIDEmpty,
		Summary:  "x509: empty authority key identifier",
		Field:    "tbsCertificate.extensions.AuthorityKeyIdentifier.keyIdentifier",
		SpecRef:  "RFC5280 s4.2.1.1",
		SpecText: "The keyIdentifier field of the authorityKeyIdentifier extension MUST be included in all certificates generated by conforming CAs",
		Category: MalformedCertificate,
	},
	{
		// Not used, as this chunk of spec contradicts another chunk: "Optional qualifiers, which MAY be present..."
		ID:       errCertificatePoliciesQualifiers,
		Summary:  "x509: CertificatePolicies extension including policy qualifiers",
		SpecRef:  "RFC5280 s4.2.1.4",
		Field:    "tbsCertificate.extensions.CertificatePolicies.policyQualifiers",
		SpecText: "this profile RECOMMENDS that policy information terms consist of only an OID",
		Category: PoorlyFormedCertificate,
	},
	{
		ID:       errCertificatePoliciesQualifierUnknown,
		Summary:  "x509: CertificatePolicies extension including unknown policy qualifier %v",
		Field:    "tbsCertificate.extensions.CertificatePolicies.policyQualifiers",
		SpecRef:  "RFC5280 s4.2.1.4",
		SpecText: "Where an OID alone is insufficient, this profile strongly recommends that the use of qualifiers be limited to those identified in this section.",
		Category: PoorlyFormedCertificate,
	},
	{
		ID:       errCertificatePoliciesQualifierUnknownAny,
		Summary:  "x509: CertificatePolicies extension including unknown policy qualifier %v for anyPolicy",
		Field:    "tbsCertificate.extensions.CertificatePolicies.policyQualifiers",
		SpecRef:  "RFC5280 s4.2.1.4",
		SpecText: "When qualifiers are used with the special policy anyPolicy, they MUST be limited to the qualifiers identified in this section.",
		Category: MalformedCertificate,
	},
	{
		ID:       errBasicConstraintsCANonCritical,
		Summary:  "x509: BasicConstraints extension non-critical in CA certificate",
		Field:    "tbsCertificate.extensions.BasicConstraints",
		SpecRef:  "RFC 5280 s4.2.1.9",
		SpecText: "Conforming CAs MUST include this extension in all CA certificates that contain public keys used to validate digital signatures on certificates and MUST mark the extension as critical in such certificates",
		Category: MalformedCertificate,
	},
	{
		ID:       errPublicKeyAlgorithmObsoleteOID,
		Summary:  "x509: public key algorithm specified with obsolete OID %v",
		Field:    "tbsCertificate.subjectPublicKeyInfo.algorithm",
		SpecRef:  "RFC3279 s2.3",
		Category: UnrecognizedValue,
	},
	{
		ID:       errAsn1InvalidValidity,
		Summary:  "%v",
		Field:    "tbsCertificate.validity",
		SpecRef:  "RFC 5280 s4.1.2.5",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1TrailingValidity,
		Summary:  "x509: trailing data after validity information",
		Field:    "tbsCertificate.validity",
		SpecRef:  "RFC 5280 s4.1.2.5",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidValidityTag,
		Summary:  "x509: invalid tag %d for validity.%s",
		Field:    "tbsCertificate.validity",
		SpecRef:  "RFC 5280 s4.1.2.5",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errDateLateForUTC,
		Summary:  "x509: date in UTCTime for validity.%s is after 2050",
		Field:    "tbsCertificate.validity",
		SpecRef:  "RFC 5280 s4.1.2.5",
		SpecText: "certificate validity dates in 2050 or later MUST be encoded as GeneralizedTime",
		Category: MalformedCertificate,
	},
	{
		ID:       errDateEarlyForGeneralized,
		Summary:  "x509: date in GeneralizedTime for validity.%s is before 2050",
		Field:    "tbsCertificate.validity",
		SpecRef:  "RFC 5280 s4.1.2.5",
		SpecText: "CAs conforming to this profile MUST always encode certificate validity dates through the year 2049 as UTCTime",
		Category: MalformedCertificate,
	},
	{
		ID:       errDateNonZulu,
		Summary:  "x509: date for validity.%s is not in Zulu time",
		Field:    "tbsCertificate.validity",
		SpecRef:  "RFC 5280 s4.1.2.5",
		SpecText: "values MUST be expressed in Greenwich Mean Time (Zulu)",
		Category: MalformedCertificate,
	},
	{
		ID:       errDateIncomplete,
		Summary:  "x509: date for validity.%s is incomplete",
		Field:    "tbsCertificate.validity",
		SpecRef:  "RFC 5280 s4.1.2.5",
		SpecText: "values ... MUST include seconds",
		Category: MalformedCertificate,
	},
	{
		ID:       errDateFraction,
		Summary:  "x509: date for validity.%s includes fractional seconds",
		Field:    "tbsCertificate.validity",
		SpecRef:  "RFC 5280 s4.1.2.5",
		SpecText: "GeneralizedTime values MUST NOT include fractional seconds",
		Category: MalformedCertificate,
	},
	{
		ID:       errAsn1InvalidSubjectDirAttrs,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.SubjectDirectoryAttributes",
		SpecRef:  "RFC 5280 s4.2.1.8",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errAsn1TrailingSubjectDirAttrs,
		Summary:  "x509: trailing data after X.509 SubjectDirectoryAttributes",
		Field:    "tbsCertificate.extensions.SubjectDirectoryAttributes",
		SpecRef:  "RFC 5280 s4.2.1.8",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       errSubjectDirAttrsEmpty,
		Summary:  "x509: empty SubjectDirectoryAttributes extension",
		Field:    "tbsCertificate.extensions.SubjectDirectoryAttributes",
		SpecRef:  "RFC 5280 s4.2.1.8",
		SpecText: "SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute",
		Category: InvalidValueRange,
	},

	{
		ID:       ErrCTPoisonExtensionPresent,
		Summary:  "x509: certificate includes critical CT poison extension",
		Field:    "tbsCertificate.extensions",
		SpecRef:  "RFC 6962 s3.1",
		SpecText: "Precertificate is constructed ... by adding a special critical poison extension ... to ensure that the Precertificate cannot be validated by a standard X.509v3 client",
		Category: MalformedCertificate,
		Fatal:    true,
	},
	{
		ID:       errAsn1InvalidSCT,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.SignedCertificateTimestampList",
		SpecRef:  "RFC 6962 s3.3",
		Category: InvalidASN1Content,
	},
	{
		ID:       errAsn1TrailingSCT,
		Summary:  "x509: trailing data after SCT information",
		Field:    "tbsCertificate.extensions.SignedCertificateTimestampList",
		SpecRef:  "RFC 6962 s3.3",
		Category: InvalidASN1Content,
	},
	{
		ID:       errAsn1InvalidSCTContents,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.SignedCertificateTimestampList",
		SpecRef:  "RFC 6962 s3.3",
		Category: InvalidASN1Content,
	},
	{
		ID:       errAsn1TrailingSCTContents,
		Summary:  "x509: trailing data after SCT information",
		Field:    "tbsCertificate.extensions.SignedCertificateTimestampList",
		SpecRef:  "RFC 6962 s3.3",
		Category: InvalidASN1Content,
	},
	{
		ID:       ErrInvalidCertList,
		Summary:  "x509: failed to parse CertificateList: %v",
		Field:    "CertificateList",
		SpecRef:  "RFC 5280 s5.1",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrTrailingCertList,
		Summary:  "x509: trailing data after CertificateList",
		Field:    "CertificateList",
		SpecRef:  "RFC 5280 s5.1",
		Category: InvalidASN1Content,
		Fatal:    true,
	},

	{
		ID:       ErrUnexpectedlyCriticalCertListExtension,
		Summary:  "x509: certificate list extension %v marked critical but expected to be non-critical",
		Field:    "tbsCertList.crlExtensions.*.critical",
		SpecRef:  "RFC 5280 s5.2",
		Category: MalformedCRL,
	},
	{
		ID:       ErrUnexpectedlyNonCriticalCertListExtension,
		Summary:  "x509: certificate list extension %v marked non-critical but expected to be critical",
		Field:    "tbsCertList.crlExtensions.*.critical",
		SpecRef:  "RFC 5280 s5.2",
		Category: MalformedCRL,
	},

	{
		ID:       ErrInvalidCertListAuthKeyID,
		Summary:  "x509: failed to unmarshal certificate-list authority key-id: %v",
		Field:    "tbsCertList.crlExtensions.*.AuthorityKeyIdentifier",
		SpecRef:  "RFC 5280 s5.2.1",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrTrailingCertListAuthKeyID,
		Summary:  "x509: trailing data after certificate list auth key ID",
		Field:    "tbsCertList.crlExtensions.*.AuthorityKeyIdentifier",
		SpecRef:  "RFC 5280 s5.2.1",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrInvalidCertListIssuerAltName,
		Summary:  "x509: failed to parse CRL issuer alt name: %v",
		Field:    "tbsCertList.crlExtensions.*.IssuerAltName",
		SpecRef:  "RFC 5280 s5.2.2",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrInvalidCertListCRLNumber,
		Summary:  "x509: failed to unmarshal certificate-list crl-number: %v",
		Field:    "tbsCertList.crlExtensions.*.CRLNumber",
		SpecRef:  "RFC 5280 s5.2.3",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrTrailingCertListCRLNumber,
		Summary:  "x509: trailing data after certificate list crl-number",
		Field:    "tbsCertList.crlExtensions.*.CRLNumber",
		SpecRef:  "RFC 5280 s5.2.3",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrNegativeCertListCRLNumber,
		Summary:  "x509: negative certificate list crl-number: %d",
		Field:    "tbsCertList.crlExtensions.*.CRLNumber",
		SpecRef:  "RFC 5280 s5.2.3",
		Category: MalformedCRL,
		Fatal:    true,
	},
	{
		ID:       ErrInvalidCertListDeltaCRL,
		Summary:  "x509: failed to unmarshal certificate-list delta-crl: %v",
		Field:    "tbsCertList.crlExtensions.*.BaseCRLNumber",
		SpecRef:  "RFC 5280 s5.2.4",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrTrailingCertListDeltaCRL,
		Summary:  "x509: trailing data after certificate list delta-crl",
		Field:    "tbsCertList.crlExtensions.*.BaseCRLNumber",
		SpecRef:  "RFC 5280 s5.2.4",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrNegativeCertListDeltaCRL,
		Summary:  "x509: negative certificate list base-crl-number: %d",
		Field:    "tbsCertList.crlExtensions.*.BaseCRLNumber",
		SpecRef:  "RFC 5280 s5.2.4",
		Category: MalformedCRL,
		Fatal:    true,
	},
	{
		ID:       ErrInvalidCertListIssuingDP,
		Summary:  "x509: failed to unmarshal certificate list issuing distribution point: %v",
		Field:    "tbsCertList.crlExtensions.*.IssuingDistributionPoint",
		SpecRef:  "RFC 5280 s5.2.5",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrTrailingCertListIssuingDP,
		Summary:  "x509: trailing data after certificate list issuing distribution point",
		Field:    "tbsCertList.crlExtensions.*.IssuingDistributionPoint",
		SpecRef:  "RFC 5280 s5.2.5",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrCertListIssuingDPMultipleTypes,
		Summary:  "x509: multiple cert types set in issuing-distribution-point: user:%v CA:%v attr:%v",
		Field:    "tbsCertList.crlExtensions.*.IssuingDistributionPoint",
		SpecRef:  "RFC 5280 s5.2.5",
		SpecText: "at most one of onlyContainsUserCerts, onlyContainsCACerts, and onlyContainsAttributeCerts may be set to TRUE.",
		Category: MalformedCRL,
		Fatal:    true,
	},
	{
		ID:       ErrCertListIssuingDPInvalidFullName,
		Summary:  "x509: failed to parse CRL issuing-distribution-point fullName: %v",
		Field:    "tbsCertList.crlExtensions.*.IssuingDistributionPoint.distributionPoint",
		SpecRef:  "RFC 5280 s5.2.5",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrInvalidCertListFreshestCRL,
		Summary:  "x509: failed to unmarshal certificate list freshestCRL: %v",
		Field:    "tbsCertList.crlExtensions.*.FreshestCRL",
		SpecRef:  "RFC 5280 s5.2.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrInvalidCertListAuthInfoAccess,
		Summary:  "x509: failed to unmarshal certificate list authority info access: %v",
		Field:    "tbsCertList.crlExtensions.*.AuthorityInfoAccess",
		SpecRef:  "RFC 5280 s5.2.7",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrTrailingCertListAuthInfoAccess,
		Summary:  "x509: trailing data after certificate list authority info access",
		Field:    "tbsCertList.crlExtensions.*.AuthorityInfoAccess",
		SpecRef:  "RFC 5280 s5.2.7",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrUnhandledCriticalCertListExtension,
		Summary:  "x509: unhandled critical extension in certificate list: %v",
		Field:    "tbsCertList.revokedCertificates.crlExtensions.*",
		SpecRef:  "RFC 5280 s5.2",
		SpecText: "If a CRL contains a critical extension that the application cannot process, then the application MUST NOT use that CRL to determine the status of certificates.",
		Category: MalformedCRL,
		Fatal:    true,
	},

	{
		ID:       ErrUnexpectedlyCriticalRevokedCertExtension,
		Summary:  "x509: revoked certificate extension %v marked critical but expected to be non-critical",
		Field:    "tbsCertList.revokedCertificates.crlEntryExtensions.*.critical",
		SpecRef:  "RFC 5280 s5.3",
		Category: MalformedCRL,
	},
	{
		ID:       ErrUnexpectedlyNonCriticalRevokedCertExtension,
		Summary:  "x509: revoked certificate extension %v marked non-critical but expected to be critical",
		Field:    "tbsCertList.revokedCertificates.crlEntryExtensions.*.critical",
		SpecRef:  "RFC 5280 s5.3",
		Category: MalformedCRL,
	},

	{
		ID:       ErrInvalidRevocationReason,
		Summary:  "x509: failed to parse revocation reason: %v",
		Field:    "tbsCertList.revokedCertificates.crlEntryExtensions.*.CRLReason",
		SpecRef:  "RFC 5280 s5.3.1",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrTrailingRevocationReason,
		Summary:  "x509: trailing data after revoked certificate reason",
		Field:    "tbsCertList.revokedCertificates.crlEntryExtensions.*.CRLReason",
		SpecRef:  "RFC 5280 s5.3.1",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrInvalidRevocationInvalidityDate,
		Summary:  "x509: failed to parse revoked certificate invalidity date: %v",
		Field:    "tbsCertList.revokedCertificates.crlEntryExtensions.*.InvalidityDate",
		SpecRef:  "RFC 5280 s5.3.2",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrTrailingRevocationInvalidityDate,
		Summary:  "x509: trailing data after revoked certificate invalidity date",
		Field:    "tbsCertList.revokedCertificates.crlEntryExtensions.*.InvalidityDate",
		SpecRef:  "RFC 5280 s5.3.2",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrInvalidRevocationIssuer,
		Summary:  "x509: failed to parse revocation issuer %v",
		Field:    "tbsCertList.revokedCertificates.crlEntryExtensions.*.CertificateIssuer",
		SpecRef:  "RFC 5280 s5.3.3",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrUnhandledCriticalRevokedCertExtension,
		Summary:  "x509: unhandled critical extension in revoked certificate: %v",
		Field:    "tbsCertList.revokedCertificates.crlEntryExtensions.*",
		SpecRef:  "RFC 5280 s5.3",
		SpecText: "If a CRL contains a critical CRL entry extension that the application cannot process, then the application MUST NOT use that CRL to determine the status of any certificates.",
		Category: MalformedCRL,
		Fatal:    true,
	},
}

func init() {
	idToError = make(map[ErrorID]Error, len(errorInfo))
	for _, info := range errorInfo {
		idToError[info.ID] = info
	}
}

// NewError builds a new x509.Error based on the template for the given id.
func NewError(id ErrorID, args ...interface{}) Error {
	var err Error
	if id >= ErrMaxID {
		err.ID = id
		err.Summary = fmt.Sprintf("Unknown error ID %v: args %+v", id, args)
		err.Fatal = true
	} else {
		err = idToError[id]
		err.Summary = fmt.Sprintf(err.Summary, args...)
	}
	return err
}
