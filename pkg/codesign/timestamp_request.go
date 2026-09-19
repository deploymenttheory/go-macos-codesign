package codesign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// TimestampExchange exchanges an RFC 3161 DER TimeStampReq for a TimeStampResp.
// Implementations own transport, deadlines and response-size limits and must
// honor ctx. AcquireTimestamp authenticates the returned token and nonce.
type TimestampExchange func(ctx context.Context, request []byte) (response []byte, err error)

// AcquireTimestamp requests a SHA-256 timestamp with 128 random nonce bits and
// certReq=true. It checks the response status, exact nonce, signature imprint,
// TSA certificate binding, purpose, dates and an explicit TSA root path before
// returning a ContentInfo token suitable for TimestampOptions.Provider.
// No HTTP client, platform trust or network dependency is linked by this helper.
func AcquireTimestamp(ctx context.Context, signature []byte, exchange TimestampExchange, roots [][]byte, now time.Time) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if exchange == nil || len(roots) == 0 || len(signature) == 0 || len(signature) > 8192 {
		return nil, invalid("timestamp exchange, TSA roots and signature required")
	}
	var random [16]byte
	_, _ = rand.Read(random[:]) // crypto/rand.Read fills the buffer or terminates.
	// Keep the nonce strictly positive without constraining its random bits.
	nonce := new(big.Int).SetBytes(append([]byte{1}, random[:]...))
	digest := sha256.Sum256(signature)
	request := derSequence([]byte{2, 1, 1}, derSequence(derAlgorithm(oidSHA256, true), derWrap(4, digest[:])), derPositive(nonce), []byte{1, 1, 255})
	response, err := exchange(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("timestamp exchange: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(response) > maxTimestampSize {
		return nil, malformed("timestamp response size")
	}
	budget := 4096
	parts, err := cmsBERChildren(response, 0x30, &budget)
	if err != nil {
		return nil, err
	}
	if len(parts) < 1 || len(parts) > 2 {
		return nil, malformed("timestamp response fields")
	}
	status, err := decodeTimestampDER[struct {
		Status  int
		Text    []asn1.RawValue `asn1:"optional"`
		Failure asn1.BitString  `asn1:"optional"`
	}](parts[0].raw)
	if err != nil {
		return nil, err
	}
	// PKIFreeText is UTF8String even when its contents also fit PrintableString.
	// Preserve its tag during canonical checks; encoding/asn1 otherwise chooses
	// PrintableString when marshaling ordinary ASCII strings such as Apple's
	// "Operation Okay" response.
	for _, raw := range status.Text {
		if raw.Class != 0 || raw.Tag != asn1.TagUTF8String || raw.IsCompound {
			return nil, malformed("timestamp status text must be UTF8String")
		}
		var message string
		if err := decodeDER(raw.FullBytes, &message); err != nil {
			return nil, err
		}
	}
	if status.Status != 0 && status.Status != 1 || status.Failure.BitLength != 0 {
		return nil, invalid("timestamp authority rejected request (status %d)", status.Status)
	}
	if len(parts) != 2 {
		return nil, malformed("successful timestamp response lacks token")
	}
	token := parts[1].raw
	info, err := VerifyTimestampToken(token, signature, roots, now)
	if err != nil {
		return nil, err
	}
	if info.nonce == nil || info.nonce.Cmp(nonce) != 0 {
		return nil, invalid("timestamp response nonce is missing or does not match request")
	}
	if info.imprintHash != crypto.SHA256 {
		return nil, invalid("timestamp response changed the requested imprint algorithm")
	}
	return bytes.Clone(token), nil
}
