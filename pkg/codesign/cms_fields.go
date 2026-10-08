package codesign

import "encoding/asn1"

// Decode each original field independently: only ContentInfo, its explicit
// wrapper, SignedData and EncapsulatedContentInfo may use indefinite BER.
// Certificate sets, signer sets and authenticated attributes remain strict DER.
// The returned internal values borrow data; parseCertificate owns certificate
// bytes before they can escape through the public CMSInfo result.
func decodeCMSFields(data []byte) (*cmsSignedData, error) {
	oid, fields, err := cmsEnvelopeFields(data)
	if err != nil {
		return nil, err
	}
	var contentType asn1.ObjectIdentifier
	if err := decodeDER(oid, &contentType); err != nil {
		return nil, err
	}
	if !contentType.Equal(oidSignedData) {
		return nil, malformed("CMS ContentInfo")
	}
	sd := new(cmsSignedData)
	if err := decodeDER(fields[0].raw, &sd.Version); err != nil {
		return nil, err
	}
	if err := decodeCMSSet(fields[1].raw, &sd.Digests); err != nil {
		return nil, err
	}
	budget := 4096
	content, err := cmsBERChildren(fields[2].raw, 0x30, &budget)
	if err != nil {
		return nil, err
	}
	if len(content) < 1 || len(content) > 2 {
		return nil, malformed("CMS encapsulated content fields")
	}
	if err := decodeDER(content[0].raw, &sd.Content.Type); err != nil {
		return nil, err
	}
	if len(content) == 2 {
		if content[1].tag != 0xa0 {
			return nil, malformed("CMS encapsulated content tag")
		}
		if err := decodeDER(content[1].raw, &sd.Content.Content); err != nil {
			return nil, err
		}
	}
	next := 3
	for _, optional := range []struct {
		tag byte
		out *asn1.RawValue
	}{{0xa0, &sd.Certificates}, {0xa1, &sd.CRLs}} {
		if next < len(fields) && fields[next].tag == optional.tag {
			if err := decodeDER(fields[next].raw, optional.out); err != nil {
				return nil, err
			}
			next++
		}
	}
	if next != len(fields)-1 {
		return nil, malformed("CMS SignedData field order")
	}
	if err := decodeCMSSet(fields[next].raw, &sd.Signers); err != nil {
		return nil, err
	}
	return sd, nil
}

func decodeCMSSet(data []byte, out any) error {
	rest, err := asn1.UnmarshalWithParams(data, out, "set")
	if err != nil {
		return malformed("CMS DER set: %v", err)
	}
	if len(rest) != 0 {
		return malformed("trailing CMS DER set data")
	}
	return nil
}
