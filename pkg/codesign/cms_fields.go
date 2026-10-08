package codesign

import (
	"context"
	"encoding/asn1"
)

// Decode each original field independently: only ContentInfo, its explicit
// wrapper, SignedData and EncapsulatedContentInfo may use indefinite BER.
// Certificate sets, signer sets and authenticated attributes remain strict DER.
// The returned internal values borrow data; parseCertificate owns certificate
// bytes before they can escape through the public CMSInfo result.
func decodeCMSFields(data []byte) (*cmsSignedData, error) {
	source := codeSource{context.Background(), byteOutput(data)}
	return decodeCMSFieldsReader(source, func(at, n uint64) ([]byte, error) { return data[at : at+n], nil })
}

func decodeCMSFieldsSource(source codeSource) (*cmsSignedData, error) {
	return decodeCMSFieldsReader(source, source.read)
}

func decodeCMSFieldsReader(source codeSource, read rangeReader) (*cmsSignedData, error) {
	oid, fields, err := cmsEnvelopeRanges(source)
	if err != nil {
		return nil, err
	}
	decode := func(field cmsBERRange, out any, set bool) error {
		raw, err := read(field.offset, field.length)
		if err != nil {
			return err
		}
		if set {
			return decodeCMSSet(raw, out)
		}
		return decodeDER(raw, out)
	}
	var contentType asn1.ObjectIdentifier
	if err := decode(oid, &contentType, false); err != nil {
		return nil, err
	}
	if !contentType.Equal(oidSignedData) {
		return nil, malformed("CMS ContentInfo")
	}
	sd := new(cmsSignedData)
	if err := decode(fields[0], &sd.Version, false); err != nil {
		return nil, err
	}
	if err := decode(fields[1], &sd.Digests, true); err != nil {
		return nil, err
	}
	budget := 4096
	content, err := cmsBERChildRanges(source, fields[2].offset, fields[2].length, 0x30, &budget)
	if err != nil {
		return nil, err
	}
	if len(content) < 1 || len(content) > 2 {
		return nil, malformed("CMS encapsulated content fields")
	}
	if err := decode(content[0], &sd.Content.Type, false); err != nil {
		return nil, err
	}
	if len(content) == 2 {
		if content[1].tag != 0xa0 {
			return nil, malformed("CMS encapsulated content tag")
		}
		if err := decode(content[1], &sd.Content.Content, false); err != nil {
			return nil, err
		}
	}
	next := 3
	for _, optional := range []struct {
		tag byte
		out *asn1.RawValue
	}{{0xa0, &sd.Certificates}, {0xa1, &sd.CRLs}} {
		if next < len(fields) && fields[next].tag == optional.tag {
			if err := decode(fields[next], optional.out, false); err != nil {
				return nil, err
			}
			next++
		}
	}
	if next != len(fields)-1 {
		return nil, malformed("CMS SignedData field order")
	}
	if err := decode(fields[next], &sd.Signers, true); err != nil {
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
