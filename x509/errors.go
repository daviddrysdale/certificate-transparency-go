package x509

import "fmt"

// To preserve error IDs, only append to this list, never insert.
const (
	ErrInvalidID ErrorID = iota
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
	ErrAsn1InvalidGeneralNames
	ErrAsn1TrailingGeneralNames
	ErrInvalidGeneralNamesTag
	ErrAsn1InvalidGeneralName
	ErrAsn1InvalidGeneralNameOther
	ErrAsn1InvalidGeneralNameOtherNotCompound
	ErrAsn1InvalidGeneralNameDirectory
	ErrAsn1InvalidGeneralNameURI
	ErrInvalidGeneralNameURI
	ErrGeneralNameIPMaskLen
	ErrGeneralNameIPLen
	ErrAsn1InvalidGeneralNameOID
	ErrInvalidGeneralNameTag
	ErrInvalidGeneralNameEmailEncoding
	ErrInvalidGeneralNameDNSEncoding
	ErrInvalidGeneralNameURIEncoding
	ErrNameConstraintsInvalidDomain
	ErrNameConstraintsInvalidEmail
	ErrNameConstraintsInvalidURI
	ErrSerialNumberNegative
	ErrSerialNumberZero
	ErrSubjectAsn1Invalid
	ErrIssuerAsn1Invalid
	ErrAsn1InvalidValidity
	ErrAsn1TrailingValidity
	ErrAsn1InvalidValidityTag
	ErrDateLateForUTC
	ErrDateEarlyForGeneralized
	ErrDateNonZulu
	ErrDateIncomplete
	ErrDateFraction
	ErrUnexpectedlyCriticalExtension
	ErrUnexpectedlyNonCriticalExtension
	ErrAsn1InvalidKeyUsageTrailingZeros
	ErrKeyUsageEmpty
	ErrKeyUsageWrongBitCount
	ErrBasicConstraintsNegativePathLen
	ErrAuthorityKeyIDEmpty
	ErrCertificatePoliciesDuplicate
	ErrCertificatePoliciesQualifierUnknown
	ErrCertificatePoliciesQualifierUnknownAny
	ErrAsn1InvalidSubjectDirAttrs
	ErrAsn1TrailingSubjectDirAttrs
	ErrSubjectDirAttrsEmpty
	ErrAuthorityInformationAccessEmpty
	ErrSubjectInformationAccessEmpty
	ErrAsn1InvalidSCT
	ErrAsn1TrailingSCT
	ErrAsn1InvalidSCTContents
	ErrAsn1TrailingSCTContents
	ErrExtensionsInOldCert
	ErrUniqueIDInV1Cert
	ErrUniqueIDNoExtsNotV2
	ErrKeyUsageCANoSign
	ErrKeyUsageNonCAKeySign
	ErrNameConstraintsNonCA
	ErrPolicyMappingsMissingPolicy
	ErrSubjectKeyIDMissingInCA
	ErrBasicConstraintsCANonCritical
	ErrBasicConstraintsNonCAPathLen
	ErrPubKeyInsecureCurve
	ErrPubKeyRSANonNullParams
	ErrPubKeyRSANonPositiveModulus
	ErrPubKeyRSAAsn1Invalid
	ErrPubKeyDSAAsn1Invalid
	ErrExtendedKeyUsageEmpty
	ErrExtendedKeyUsageEmptyOID
	ErrAsn1InvalidIPAddrBlocks
	ErrAsn1TrailingIPAddrBlocks
	ErrIPAddressFamilyLength
	ErrAsn1InvalidIPAddressOrRange
	ErrAsn1InvalidIPAddrBlockAddress
	ErrAsn1InvalidIPAddrBlockAddressRange
	ErrAsn1InvalidIPAddrBlockAddressType
	ErrAsn1InvalidASIdOrRange
	ErrAsn1TrailingASIdOrRange
	ErrAsn1InvalidASId
	ErrAsn1InvalidASRange
	ErrAsn1InvalidASType
	ErrAsn1InvalidASIdentifiers
	ErrAsn1TrailingASIdentifiers

	ErrMaxID
)

// idToError gives a template x509.Error for each defined ErrorID; where the Summary
// field may hold format specifiers that take field parameters.
var idToError map[ErrorID]Error

var errorInfo = []Error{
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

	{
		ID:       ErrAsn1InvalidGeneralNames,
		Summary:  "x509: failed to parse %s GeneralNames: %v",
		Field:    "GeneralNames",
		SpecRef:  "RFC 5280 s4.2.1.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrAsn1TrailingGeneralNames,
		Summary:  "x509: trailing data after %s GeneralNames",
		Field:    "GeneralNames",
		SpecRef:  "RFC 5280 s4.2.1.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrInvalidGeneralNamesTag,
		Summary:  "x509: invalid ASN.1 tag %d/class %d for %s GeneralNames",
		Field:    "GeneralNames",
		SpecRef:  "RFC 5280 s4.2.1.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrAsn1InvalidGeneralName,
		Summary:  "x509: failed to parse %s GeneralName: %v",
		Field:    "GeneralName",
		SpecRef:  "RFC 5280 s4.2.1.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrAsn1InvalidGeneralNameOther,
		Summary:  "x509: failed to parse %s GeneralName.otherName: %v",
		Field:    "GeneralName.otherName",
		SpecRef:  "RFC 5280 s4.2.1.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrAsn1InvalidGeneralNameOtherNotCompound,
		Summary:  "x509: %s GeneralName.OtherName not compound",
		Field:    "GeneralName.otherName",
		SpecRef:  "RFC 5280 s4.2.1.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrAsn1InvalidGeneralNameDirectory,
		Summary:  "x509: failed to parse %s GeneralName.directoryName: %v",
		Field:    "GeneralName.directoryName",
		SpecRef:  "RFC 5280 s4.2.1.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrAsn1InvalidGeneralNameURI,
		Summary:  "x509: failed to parse %s GeneralName.uniformResourceIdentifier %q: %v",
		Field:    "GeneralName.uniformResourceIdentifier",
		SpecRef:  "RFC 5280 s4.2.1.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrInvalidGeneralNameURI,
		Summary:  "x509: failed to parse %s GeneralName.uniformResourceIdentifier %q: invalid domain",
		Field:    "GeneralName.uniformResourceIdentifier",
		SpecRef:  "RFC 5280 s4.2.1.6",
		Category: MalformedCertificate,
		Fatal:    true,
	},
	{
		ID:       ErrGeneralNameIPMaskLen,
		Summary:  "x509: %s GeneralName.iPAddress with IP/mask address of length %d",
		Field:    "GeneralName.ipAddress",
		SpecRef:  "RFC5280 s4.2.1.10",
		SpecText: "For IPv4 addresses, the iPAddress field of GeneralName MUST contain eight (8) octets...For IPv6 addresses, the iPAddress field MUST contain 32 octets",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrGeneralNameIPLen,
		Summary:  "x509: %s GeneralName.iPAddress with IP address of length %d",
		Field:    "GeneralName.ipAddress",
		SpecRef:  "RFC5280 s4.2.1.6",
		SpecText: "For IP version 4, as specified in [RFC791], the octet string MUST contain exactly four octets.  For IP version 6, as specified in [RFC2460], the octet string MUST contain exactly sixteen octets",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrAsn1InvalidGeneralNameOID,
		Summary:  "x509: invalid ASN.1 OBJECT-IDENTIFIER in %s GeneralName: %v",
		Field:    "GeneralName.registeredID",
		SpecRef:  "RFC 5280 s4.1.2.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrInvalidGeneralNameTag,
		Summary:  "x509: unknown tag %d for %s GeneralName",
		Field:    "GeneralName",
		SpecRef:  "RFC 5280 s4.2.1.6",
		Category: InvalidASN1Content,
	},
	{
		ID:       ErrInvalidGeneralNameEmailEncoding,
		Summary:  "x509: invalid email altName contents encoding",
		Field:    "GeneralName.rfc822Name",
		SpecRef:  "RFC 5280 s4.2.1.6",
		Category: InvalidASN1Content,
	},
	{
		ID:       ErrInvalidGeneralNameDNSEncoding,
		Summary:  "x509: invalid DNS altName contents encoding",
		Field:    "GeneralName.dNSName",
		SpecRef:  "RFC 5280 s4.2.1.6",
		Category: InvalidASN1Content,
	},
	{
		ID:       ErrInvalidGeneralNameURIEncoding,
		Summary:  "x509: invalid URI altName contents encoding",
		Field:    "GeneralName.uniformResourceIdentifier",
		SpecRef:  "RFC 5280 s4.2.1.6",
		Category: InvalidASN1Content,
	},
	{
		ID:       ErrNameConstraintsInvalidDomain,
		Summary:  "x509: failed to parse dnsName constraint %q",
		Field:    "NameConstraints.*.base.dNSName",
		SpecRef:  "RFC 5280 s4.2.1.10",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrNameConstraintsInvalidEmail,
		Summary:  "x509: failed to parse rfc822Name constraint %q",
		Field:    "NameConstraints.*.base.rfc822Name",
		SpecRef:  "RFC 5280 s4.2.1.10",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrNameConstraintsInvalidURI,
		Summary:  "x509: failed to parse URI constraint %q",
		Field:    "NameConstraints.*.base.uniformResourceIdentifier",
		SpecRef:  "RFC 5280 s4.2.1.10",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrSerialNumberNegative,
		Summary:  "x509: negative serial number",
		Field:    "tbsCertificate.serialNumber",
		SpecRef:  "RFC 5280 s4.1.2.2",
		SpecText: "The serial number MUST be a positive integer",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrSerialNumberZero,
		Summary:  "x509: zero serial number",
		Field:    "tbsCertificate.serialNumber",
		SpecRef:  "RFC 5280 s4.1.2.2",
		SpecText: "The serial number MUST be a positive integer",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrSubjectAsn1Invalid,
		Summary:  "x509: subject strict parse failure: %v",
		Field:    "tbsCertificate.Subject",
		SpecRef:  "RFC 5280 s4.1.2.6",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrIssuerAsn1Invalid,
		Summary:  "x509: issuer strict parse failure: %v",
		Field:    "tbsCertificate.Issuer",
		SpecRef:  "RFC 5280 s4.1.2.4",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrAsn1InvalidValidity,
		Summary:  "%v",
		Field:    "tbsCertificate.validity",
		SpecRef:  "RFC 5280 s4.1.2.5",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrAsn1TrailingValidity,
		Summary:  "x509: trailing data after validity information",
		Field:    "tbsCertificate.validity",
		SpecRef:  "RFC 5280 s4.1.2.5",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrAsn1InvalidValidityTag,
		Summary:  "x509: invalid tag %d for validity.%s",
		Field:    "tbsCertificate.validity",
		SpecRef:  "RFC 5280 s4.1.2.5",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrDateLateForUTC,
		Summary:  "x509: date in UTCTime for validity.%s is after 2050",
		Field:    "tbsCertificate.validity",
		SpecRef:  "RFC 5280 s4.1.2.5",
		SpecText: "certificate validity dates in 2050 or later MUST be encoded as GeneralizedTime",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrDateEarlyForGeneralized,
		Summary:  "x509: date in GeneralizedTime for validity.%s is before 2050",
		Field:    "tbsCertificate.validity",
		SpecRef:  "RFC 5280 s4.1.2.5",
		SpecText: "CAs conforming to this profile MUST always encode certificate validity dates through the year 2049 as UTCTime",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrDateNonZulu,
		Summary:  "x509: date for validity.%s is not in Zulu time",
		Field:    "tbsCertificate.validity",
		SpecRef:  "RFC 5280 s4.1.2.5",
		SpecText: "values MUST be expressed in Greenwich Mean Time (Zulu)",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrDateIncomplete,
		Summary:  "x509: date for validity.%s is incomplete",
		Field:    "tbsCertificate.validity",
		SpecRef:  "RFC 5280 s4.1.2.5",
		SpecText: "values ... MUST include seconds",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrDateFraction,
		Summary:  "x509: date for validity.%s includes fractional seconds",
		Field:    "tbsCertificate.validity",
		SpecRef:  "RFC 5280 s4.1.2.5",
		SpecText: "GeneralizedTime values MUST NOT include fractional seconds",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrUnexpectedlyCriticalExtension,
		Summary:  "x509: extension %v marked as critical but expected to be non-critical",
		Field:    "tbsCertificate.extensions.*.critical",
		SpecRef:  "RFC 5280 s4.2",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrUnexpectedlyNonCriticalExtension,
		Summary:  "x509: extension %v marked as non-critical but expected to be critical",
		Field:    "tbsCertificate.extensions.*.critical",
		SpecRef:  "RFC 5280 s4.2",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrAsn1InvalidKeyUsageTrailingZeros,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.KeyUsage",
		SpecRef:  "RFC 5280 s4.2.1.3",
		Category: InvalidASN1Content,
	},
	{
		ID:       ErrKeyUsageEmpty,
		Summary:  "x509: KeyUsage extension with no bits set",
		Field:    "tbsCertificate.extensions.KeyUsage",
		SpecRef:  "RFC5280 s4.2.1.3",
		SpecText: "When the keyUsage extension appears in a certificate, at least one of the bits MUST be set to 1",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrKeyUsageWrongBitCount,
		Summary:  "x509: KeyUsage extension with incorrect number of bits (%d not 9)",
		Field:    "tbsCertificate.extensions.KeyUsage",
		SpecRef:  "RFC5280 s4.2.1.3",
		SpecText: "BIT STRING {... decipherOnly (8) }",
		Category: InvalidValueRange,
	},
	{
		ID:       ErrBasicConstraintsNegativePathLen,
		Summary:  "x509: BasicConstraints extension with negative path len (%d)",
		Field:    "tbsCertificate.extensions.BasicConstraints.pathLenConstraint",
		SpecRef:  "RFC5280 s4.2.1.9",
		SpecText: "Where it appears, the pathLenConstraint field MUST be greater than or equal to zero",
		Category: InvalidASN1Content,
	},
	{
		ID:       ErrAuthorityKeyIDEmpty,
		Summary:  "x509: empty authority key identifier",
		Field:    "tbsCertificate.extensions.AuthorityKeyIdentifier.keyIdentifier",
		SpecRef:  "RFC5280 s4.2.1.1",
		SpecText: "The keyIdentifier field of the authorityKeyIdentifier extension MUST be included in all certificates generated by conforming CAs",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrCertificatePoliciesDuplicate,
		Summary:  "x509: duplicate policy %v in CertificatePolicies extension",
		Field:    "tbsCertificate.extensions.CertificatePolicies.policyIdentifier",
		SpecRef:  "RFC5280 s4.2.1.4",
		SpecText: "A certificate policy OID MUST NOT appear more than once in a certificate policies extension",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrCertificatePoliciesQualifierUnknown,
		Summary:  "x509: CertificatePolicies extension including unknown policy qualifier %v",
		Field:    "tbsCertificate.extensions.CertificatePolicies.policyQualifiers",
		SpecRef:  "RFC5280 s4.2.1.4",
		SpecText: "Where an OID alone is insufficient, this profile strongly recommends that the use of qualifiers be limited to those identified in this section.",
		Category: PoorlyFormedCertificate,
	},
	{
		ID:       ErrCertificatePoliciesQualifierUnknownAny,
		Summary:  "x509: CertificatePolicies extension including unknown policy qualifier %v for anyPolicy",
		Field:    "tbsCertificate.extensions.CertificatePolicies.policyQualifiers",
		SpecRef:  "RFC5280 s4.2.1.4",
		SpecText: "When qualifiers are used with the special policy anyPolicy, they MUST be limited to the qualifiers identified in this section.",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrAsn1InvalidSubjectDirAttrs,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.SubjectDirectoryAttributes",
		SpecRef:  "RFC 5280 s4.2.1.8",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrAsn1TrailingSubjectDirAttrs,
		Summary:  "x509: trailing data after X.509 SubjectDirectoryAttributes",
		Field:    "tbsCertificate.extensions.SubjectDirectoryAttributes",
		SpecRef:  "RFC 5280 s4.2.1.8",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	{
		ID:       ErrSubjectDirAttrsEmpty,
		Summary:  "x509: empty SubjectDirectoryAttributes extension",
		Field:    "tbsCertificate.extensions.SubjectDirectoryAttributes",
		SpecRef:  "RFC 5280 s4.2.1.8",
		SpecText: "SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute",
		Category: InvalidValueRange,
	},
	{
		ID:       ErrAuthorityInformationAccessEmpty,
		Summary:  "x509: empty AuthorityInfoAccess extension",
		Field:    "tbsCertificate.extensions.AuthorityInfoAccessSyntax",
		SpecRef:  "RFC5280 s4.2.2.2",
		SpecText: "AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription",
		Category: InvalidASN1Content,
	},
	{
		ID:       ErrSubjectInformationAccessEmpty,
		Summary:  "x509: empty SubjectInfoAccess extension",
		Field:    "tbsCertificate.extensions.SubjectInfoAccessSyntax",
		SpecRef:  "RFC5280 s4.2.2.2",
		SpecText: "SubjectInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription",
		Category: InvalidASN1Content,
	},
	{
		ID:       ErrAsn1InvalidSCT,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.SignedCertificateTimestampList",
		SpecRef:  "RFC 6962 s3.3",
		Category: InvalidASN1Content,
	},
	{
		ID:       ErrAsn1TrailingSCT,
		Summary:  "x509: trailing data after SCT information",
		Field:    "tbsCertificate.extensions.SignedCertificateTimestampList",
		SpecRef:  "RFC 6962 s3.3",
		Category: InvalidASN1Content,
	},
	{
		ID:       ErrAsn1InvalidSCTContents,
		Summary:  "%v",
		Field:    "tbsCertificate.extensions.SignedCertificateTimestampList",
		SpecRef:  "RFC 6962 s3.3",
		Category: InvalidASN1Content,
	},
	{
		ID:       ErrAsn1TrailingSCTContents,
		Summary:  "x509: trailing data after SCT information",
		Field:    "tbsCertificate.extensions.SignedCertificateTimestampList",
		SpecRef:  "RFC 6962 s3.3",
		Category: InvalidASN1Content,
	},
	{
		ID:       ErrExtensionsInOldCert,
		Summary:  "x509: extensions present in non-V3 (v%d) certificate",
		Field:    "tbsCertificate.extensions",
		SpecRef:  "RFC5280 s4.1.2.9",
		SpecText: "Extensions...MUST only appear if the versions is 3",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrUniqueIDInV1Cert,
		Summary:  "x509: SubjectUniqueIdentifier / IssuerUniqueIdentifier present in V1 cert",
		Field:    "tbsCertificate.*UniqueID",
		SpecRef:  "RFC5280 s4.1.2.8",
		SpecText: "These fields MUST NOT appear if the version is 1",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrUniqueIDNoExtsNotV2,
		Summary:  "x509: non-V2 (V%d) certificate with UniqueIdentifier but no extensions",
		Field:    "tbsCertficiate.*UniqueID",
		SpecRef:  "RFC5280 s4.1.2.1",
		SpecText: "If no extensions are present, but a UniqueIdentifier is present, the version SHOULD be 2",
		Category: PoorlyFormedCertificate,
	},
	{
		ID:       ErrKeyUsageCANoSign,
		Summary:  "x509: CA certificate missing keyCertSign bit in KeyUsage",
		Field:    "tbsCertificate.extensions.KeyUsage",
		SpecRef:  "RFC5280 s4.2.1.3",
		SpecText: "If the keyCertSign bit is asserted, then the cA bit in the basic constraints extension (Section 4.2.1.9) MUST also be asserted",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrKeyUsageNonCAKeySign,
		Summary:  "x509: non-CA certificate with keyCertSign bit in KeyUsage",
		Field:    "tbsCertificate.extensions.KeyUsage",
		SpecRef:  "RFC5280 s4.2.1.3",
		SpecText: "If the cA boolean is not asserted, then the keyCertSign bit in the key usage extension MUST NOT be asserted.",
		Category: MalformedCertificate,
	},

	{
		ID:       ErrNameConstraintsNonCA,
		Summary:  "x509: NameConstraints extension in non-CA certificate",
		Field:    "tbsCertificate.extensions.NameConstraints",
		SpecRef:  "RFC5280 s4.2.1.10",
		SpecText: "The name constraints extension ... MUST be used only in a CA certificate",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrPolicyMappingsMissingPolicy,
		Summary:  "x509: PolicyMapping extension referencing unspecified policy %v",
		SpecRef:  "RFC5280 s4.2.1.5",
		SpecText: "Each issuerDomainPolicy named in the policy mappings extension SHOULD also be asserted in a certificate policies extension in the same certificate.",
		Category: PoorlyFormedCertificate,
	},
	{
		ID:       ErrSubjectKeyIDMissingInCA,
		Summary:  "x509: SubjectKeyIdentifier missing in CA certificate",
		SpecRef:  "RFC5280 s4.2.1.2",
		Field:    "tbsCertificate.extensions.SubjectKeyIdentifier",
		SpecText: "this extension MUST appear in all conforming CA certificates",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrBasicConstraintsCANonCritical,
		Summary:  "x509: BasicConstraints extension non-critical in CA certificate",
		Field:    "tbsCertificate.extensions.BasicConstraints",
		SpecRef:  "RFC 5280 s4.2.1.9",
		SpecText: "Conforming CAs MUST include this extension in all CA certificates that contain public keys used to validate digital signatures on certificates and MUST mark the extension as critical in such certificates",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrBasicConstraintsNonCAPathLen,
		Summary:  "x509: BasicConstraints extension with non-zero %d pathLen in non-CA certificate",
		Field:    "tbsCertificate.extensions.BasicConstraints",
		SpecRef:  "RFC 5280 s4.2.1.9",
		SpecText: "The pathLenConstraint field is meaningful only if the cA boolean is asserted",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrPubKeyInsecureCurve,
		Summary:  "x509: insecure pubkey curve (%s) specified",
		Field:    "tbsCertificate.subjectPublicKeyInfo.algorithm",
		SpecRef:  "RFC 5280 s4.1.2.7",
		Category: InsecureAlgorithm,
	},
	{
		ID:       ErrPubKeyRSANonNullParams,
		Summary:  "x509: RSA key missing NULL parameters",
		Field:    "tbsCertificate.subjectPublicKeyInfo.algorithm",
		SpecRef:  "RFC 3279 s2.2.1",
		SpecText: "the parameters component of that type SHALL be the ASN.1 type NULL",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrPubKeyRSANonPositiveModulus,
		Summary:  "x509: RSA modulus is not a positive number",
		Field:    "tbsCertificate.subjectPublicKeyInfo.RSAPublicKey",
		SpecRef:  "RFC 3279 s2.3.1",
		Category: InsecureAlgorithm,
	},
	{
		ID:       ErrPubKeyRSAAsn1Invalid,
		Summary:  "x509: RSA key strict parse failure: %v",
		Field:    "tbsCertificate.subjectPublicKeyInfo.RSAPublicKey",
		SpecRef:  "RFC 3279 s2.3.1",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrPubKeyDSAAsn1Invalid,
		Summary:  "x509: DSA key strict parse failure: %v",
		Field:    "tbsCertificate.subjectPublicKeyInfo.DSAPublicKey",
		SpecRef:  "RFC 3279 s2.3.2",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrPubKeyRSANonNullParams,
		Summary:  "x509: RSA key missing NULL parameters",
		Field:    "tbsCertificate.subjectPublicKeyInfo.algorithm",
		SpecRef:  "RFC 3279 s2.2.1",
		SpecText: "the parameters component of that type SHALL be the ASN.1 type NULL",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrExtendedKeyUsageEmpty,
		Summary:  "x509: empty ExtendedKeyUsage",
		Field:    "tbsCertificate.extensions.ExtKeyUsageSyntax",
		SpecRef:  "RFC 5280 s4.2.1.12",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrExtendedKeyUsageEmptyOID,
		Summary:  "x509: empty ExtendedKeyUsage OID value",
		Field:    "tbsCertificate.extensions.ExtKeyUsageSyntax",
		SpecRef:  "RFC 5280 s4.2.1.12",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrAsn1InvalidIPAddrBlocks,
		Summary:  "x509: failed to asn1.Unmarshal ipAddrBlocks extension: %v",
		Field:    "tbsCertificate.extensions.IPAddrBlocks",
		SpecRef:  "RFC 3779 s2.2.3",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrAsn1TrailingIPAddrBlocks,
		Summary:  "x509: trailing data after ipAddrBlocks extension",
		Field:    "tbsCertificate.extensions.IPAddrBlocks",
		SpecRef:  "RFC 3779 s2.2.3",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrIPAddressFamilyLength,
		Summary:  "x509: invalid address family length (%d) for ipAddrBlock.addressFamily",
		Field:    "tbsCertificate.extensions.IPAddrBlocks.addressFamily",
		SpecRef:  "RFC 3779 s2.2.3",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrAsn1InvalidIPAddressOrRange,
		Summary:  "x509: failed to asn1.Unmarshal ipAddrBlocks[%d].ipAddressChoice.addressesOrRanges: %v",
		Field:    "tbsCertificate.extensions.IPAddrBlocks.addressFamily.addressesOrRanges",
		SpecRef:  "RFC 3779 s2.2.3",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrAsn1InvalidIPAddrBlockAddress,
		Summary:  "x509: failed to asn1.Unmarshal ipAddrBlocks[%d].ipAddressChoice.addressesOrRanges[%d].addressPrefix: %v",
		Field:    "tbsCertificate.extensions.IPAddrBlocks.addressFamily.addressesOrRanges.addressPrefix",
		SpecRef:  "RFC 3779 s2.2.3",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrAsn1InvalidIPAddrBlockAddressRange,
		Summary:  "x509: failed to asn1.Unmarshal ipAddrBlocks[%d].ipAddressChoice.addressesOrRanges[%d].addressRange: %v",
		Field:    "tbsCertificate.extensions.IPAddrBlocks.addressFamily.addressesOrRanges.addressRange",
		SpecRef:  "RFC 3779 s2.2.3",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrAsn1InvalidIPAddrBlockAddressType,
		Summary:  "x509: unexpected ASN.1 type in ipAddrBlocks[%d].ipAddressChoice.addressesOrRanges[%d]: %+v",
		Field:    "tbsCertificate.extensions.IPAddrBlocks.addressFamily.addressesOrRanges",
		SpecRef:  "RFC 3779 s2.2.3",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrAsn1InvalidASIdOrRange,
		Summary:  "x509: failed to asn1.Unmarshal ASIdentifiers.asIdsOrRanges: %v",
		Field:    "tbsCertificate.extensions.ASIdentifiers.asIdsOrRanges",
		SpecRef:  "RFC 3779 s2.3.2",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrAsn1TrailingASIdOrRange,
		Summary:  "x509: trailing data after ASIdentifiers.asIdsOrRanges",
		Field:    "tbsCertificate.extensions.ASIdentifiers.asIdsOrRanges",
		SpecRef:  "RFC 3779 s2.3.2",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrAsn1InvalidASId,
		Summary:  "x509: failed to asn1.Unmarshal ASIdentifiers.asIdsOrRanges[%d].id: %v",
		Field:    "tbsCertificate.extensions.ASIdentifiers.asIdsOrRanges.id",
		SpecRef:  "RFC 3779 s2.3.2",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrAsn1InvalidASRange,
		Summary:  "x509: failed to asn1.Unmarshal ASIdentifiers.asIdsOrRanges[%d].range: %v",
		Field:    "tbsCertificate.extensions.ASIdentifiers.asIdsOrRanges.range",
		SpecRef:  "RFC 3779 s2.3.2",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrAsn1InvalidASType,
		Summary:  "x509: unexpected value in ASIdentifiers.asIdsOrRanges[%d]: %+v",
		Field:    "tbsCertificate.extensions.ASIdentifiers.asIdsOrRanges",
		SpecRef:  "RFC 3779 s2.3.2",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrAsn1InvalidASIdentifiers,
		Summary:  "x509: failed to asn1.Unmarshal ASIdentifiers extension: %v",
		Field:    "tbsCertificate.extensions.ASIdentifiers",
		SpecRef:  "RFC 3779 s2.3.2",
		Category: MalformedCertificate,
	},
	{
		ID:       ErrAsn1TrailingASIdentifiers,
		Summary:  "x509: trailing data after ASIdentifiers extension",
		Field:    "tbsCertificate.extensions.ASIdentifiers",
		SpecRef:  "RFC 3779 s2.3.2",
		Category: MalformedCertificate,
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
