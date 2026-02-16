package tlstap

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

var oidTranslationMap = map[string]string{
	"2.5.4.0":  "objectClass",
	"2.5.4.1":  "aliasedEntryName",
	"2.5.4.2":  "knowledgeInformation",
	"2.5.4.3":  "commonName",
	"2.5.4.4":  "surname",
	"2.5.4.5":  "serialNumber",
	"2.5.4.6":  "countryName",
	"2.5.4.7":  "localityName",
	"2.5.4.8":  "stateOrProvinceName",
	"2.5.4.9":  "streetAddress",
	"2.5.4.10": "organizationName",
	"2.5.4.11": "organizationUnitName",
	"2.5.4.12": "title",
	"2.5.4.13": "description",
	"2.5.4.14": "searchGuide",
	"2.5.4.15": "businessCategory",
	"2.5.4.16": "postalAddress",
	"2.5.4.17": "postalCode",
	"2.5.4.18": "postOfficeBox",
	"2.5.4.19": "physicalDeliveryOfficeName",
	"2.5.4.20": "telephoneNumber",
	"2.5.4.21": "telexNumber",
	"2.5.4.22": "teletexTerminalIdentifier",
	"2.5.4.23": "facsimileTelephoneNumber",
	"2.5.4.24": "x121Address",
	"2.5.4.25": "internationalISDNNumber",
	"2.5.4.26": "registeredAddress",
	"2.5.4.27": "destinationIndicator",
	"2.5.4.28": "preferredDeliveryMethod",
	"2.5.4.29": "presentationAddress",
	"2.5.4.30": "supportedApplicationContext",
	"2.5.4.31": "member",
	"2.5.4.32": "owner",
	"2.5.4.33": "roleOccupant",
	"2.5.4.34": "seeAlso",
	"2.5.4.35": "userPassword",
	"2.5.4.36": "userCertificate",
	"2.5.4.37": "cACertificate",
	"2.5.4.38": "authorityRevocationList",
	"2.5.4.39": "certificateRevocationList",
	"2.5.4.40": "crossCertificatePair",
	"2.5.4.41": "name",
	"2.5.4.42": "givenName",
	"2.5.4.43": "initials",
	"2.5.4.44": "generationQualifier",
	"2.5.4.45": "uniqueIdentifier",
	"2.5.4.46": "dnQualifier",
	"2.5.4.47": "enhancedSearchGuide",
	"2.5.4.48": "protocolInformation",
	"2.5.4.49": "distinguishedName",
	"2.5.4.50": "uniqueMember",
	"2.5.4.51": "houseIdentifier",
	"2.5.4.52": "supportedAlgorithms",
	"2.5.4.53": "deltaRevocationList",
	"2.5.4.54": "dmdName",
	"2.5.4.55": "clearance",
	"2.5.4.56": "defaultDirQop",
	"2.5.4.57": "attributeIntegrityInfo",
	"2.5.4.58": "attributeCertificate",
	"2.5.4.59": "attributeCertificateRevocationList",
	"2.5.4.60": "confKeyInfo",
	"2.5.4.61": "aACertificate",
	"2.5.4.62": "attributeDescriptorCertificate",
	"2.5.4.63": "attributeAuthorityRevocationList",
	"2.5.4.64": "family-information",
	"2.5.4.65": "pseudonym",
	"2.5.4.66": "communicationsService",
	"2.5.4.67": "communicationsNetwork",
	"2.5.4.68": "certificationPracticeStmt",
	"2.5.4.69": "certificatePolicy",
	"2.5.4.70": "pkiPath",
	"2.5.4.71": "privPolicy",
	"2.5.4.72": "role",
	"2.5.4.73": "delegationPath",
	"2.5.4.74": "protPrivPolicy",
	"2.5.4.75": "xMLPrivilegeInfo",
	"2.5.4.76": "xmlPrivPolicy",
	"2.5.4.77": "uuidpair",
	"2.5.4.78": "tagOid",
	"2.5.4.79": "uiiFormat",
	"2.5.4.80": "uiiInUrh",
	"2.5.4.81": "contentUrl",
	"2.5.4.82": "permission",
	"2.5.4.83": "uri",
	"2.5.4.84": "pwdAttribute",
	"2.5.4.85": "userPwd",
	"2.5.4.86": "urn",
	"2.5.4.87": "url",
	"2.5.4.88": "utmCoordinates",
	"2.5.4.89": "urnC",
	"2.5.4.90": "uii",
	"2.5.4.91": "epc",
	"2.5.4.92": "tagAfi",
	"2.5.4.93": "epcFormat",
	"2.5.4.94": "epcInUrn",
	"2.5.4.95": "ldapUrl",
	"2.5.4.96": "ldapUrl",
	"2.5.4.97": "organizationIdentifier",
}

func translateOid(oid asn1.ObjectIdentifier) string {
	translation, ok := oidTranslationMap[oid.String()]
	if ok {
		return translation
	}

	return oid.String()
}

func decodeAsn1Value(raw []byte) (string, error) {
	var sb strings.Builder
	return decodeAsn1Internal(raw, &sb)
}

func decodeAsn1Internal(raw []byte, sb *strings.Builder) (string, error) {
	var dec asn1.RawValue
	_, err := asn1.Unmarshal(raw, &dec)
	if err != nil {
		return "", err
	}

	if dec.Class != asn1.ClassUniversal {
		sb.WriteString(fmt.Sprintf("(unhandled ASN1 class: %d; raw: %s)", dec.Class, hex.EncodeToString(raw)))
	}

	switch dec.Tag {
	case asn1.TagBoolean:
		var b bool
		if _, err := asn1.Unmarshal(raw, &b); err != nil {
			return "", err
		}

		sb.WriteString(fmt.Sprintf("(bool: %v)", b))
	case asn1.TagInteger:
		var i int64
		if _, err := asn1.Unmarshal(raw, &i); err != nil {
			return "", err
		}

		sb.WriteString(fmt.Sprintf("(integer: %d)", i))
	case asn1.TagOctetString:
		var b []byte
		if _, err := asn1.Unmarshal(raw, &b); err != nil {
			return "", err
		}

		sb.WriteString(fmt.Sprintf("(octetstring: %s)", hex.EncodeToString(b)))
	case asn1.TagBitString:
		var bs asn1.BitString
		if _, err := asn1.Unmarshal(raw, &bs); err != nil {
			return "", err
		}

		sb.WriteString(fmt.Sprintf("(bitstring: %v)", bs))
	case asn1.TagGeneralizedTime, asn1.TagUTCTime:
		var t time.Time
		if _, err := asn1.Unmarshal(raw, &t); err != nil {
			return "", err
		}

		sb.WriteString(fmt.Sprintf("(time: %v)", t))
	case asn1.TagEnum:
		var enum asn1.Enumerated
		if _, err := asn1.Unmarshal(raw, &enum); err != nil {
			return "", err
		}

		sb.WriteString(fmt.Sprintf("(enum: %d)", enum))
	case asn1.TagOID:
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(raw, &oid); err != nil {
			return "", err
		}

		sb.WriteString(fmt.Sprintf("(OID: %s)", translateOid(oid)))
	case asn1.TagSequence:
		var seq []asn1.RawValue
		if _, err := asn1.Unmarshal(raw, &seq); err != nil {
			return "", err
		}

		var parts []string
		var subSb strings.Builder
		for _, e := range seq {
			decodeAsn1Internal(e.FullBytes, &subSb)
			parts = append(parts, subSb.String())
			subSb.Reset()
		}

		sb.WriteString(fmt.Sprintf("(sequence (%d): [%s])", len(parts), strings.Join(parts, ", ")))
	case asn1.TagSet:
		var set []asn1.RawValue
		if _, err := asn1.Unmarshal(dec.Bytes, &set); err != nil {
			return "", err
		}

		var parts []string
		var subSb strings.Builder
		for _, e := range set {
			decodeAsn1Internal(e.FullBytes, &subSb)
			parts = append(parts, subSb.String())
			subSb.Reset()
		}

		sb.WriteString(fmt.Sprintf("(set (%d): [%s])", len(parts), strings.Join(parts, ", ")))
	case asn1.TagPrintableString, asn1.TagUTF8String, asn1.TagIA5String, asn1.TagNumericString:
		var str string
		if _, err := asn1.Unmarshal(raw, &str); err != nil {
			return "", err
		}

		sb.WriteString(fmt.Sprintf("(string: %s)", str))
	default:
		sb.WriteString(fmt.Sprintf("(unhandled ASN1 tag: %d; raw: %s)", dec.Tag, hex.EncodeToString(raw)))
	}

	return sb.String(), nil
}
