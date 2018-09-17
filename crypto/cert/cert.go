// cert.go - Cryptographic certificate library.
// Copyright (C) 2018  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package cert provides a cryptographic certicate library.
package cert

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"

	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/ugorji/go/codec"
)

const (
	// CertVersion is the certificate formate version.
	CertVersion = 0

	// CertKeyType is the type of key used to make the signature.
	CertKeyType = "ed25519"

	hourSeconds = 60 * 60
)

// Signature is a cryptographic signature
// which has an associated signer ID.
type Signature struct {
	// Identity is the identity of the signer.
	Identity []byte
	// Payload is the actual signature value.
	Payload []byte
}

// Certificate structure for serializing certificates.
type Certificate struct {
	// Version is the certificate format version.
	Version uint32

	// Type indicates the type of certificate.
	Type string

	// Expiration is hours since Unix epoch.
	Expiration uint64

	// CertKeyType indicates the type of key
	// that is certified by this certificate.
	CertKeyType string

	// Certified is the data that is certified by
	// this certificate.
	Certified []byte

	// Signatures are the signature of the certificate.
	Signatures []Signature
}

func (c *Certificate) message() ([]byte, error) {
	message := new(bytes.Buffer)
	err := binary.Write(message, binary.LittleEndian, c.Version)
	if err != nil {
		return nil, err
	}
	_, err = message.Write([]byte(c.Type))
	if err != nil {
		return nil, err
	}
	err = binary.Write(message, binary.LittleEndian, c.Expiration)
	if err != nil {
		return nil, err
	}
	_, err = message.Write([]byte(c.CertKeyType))
	if err != nil {
		return nil, err
	}
	_, err = message.Write([]byte(c.Certified))
	return message.Bytes(), err
}

// CreateCertificate uses the given privateKey to create a
// certificate that signs the given publicKey.
func CreateCertificate(signingKey *eddsa.PrivateKey, toSign []byte, certType string, expiration uint64) ([]byte, error) {
	cert := Certificate{
		Version:     CertVersion,
		Type:        certType,
		Expiration:  expiration,
		CertKeyType: CertKeyType,
		Certified:   toSign,
	}
	mesg, err := cert.message()
	if err != nil {
		return nil, err
	}
	cert.Signatures = []Signature{
		Signature{
			Identity: signingKey.PublicKey().Bytes(),
			Payload:  signingKey.Sign(mesg),
		},
	}
	cborHandle := new(codec.CborHandle)
	out := []byte{}
	enc := codec.NewEncoderBytes(&out, cborHandle)
	err = enc.Encode(&cert)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// VerifyCertificate returns true if the given certificate is signed by
// the given public key.
func VerifyCertificate(rawCert []byte, publicKey *eddsa.PublicKey) (bool, error) {
	cborHandle := new(codec.CborHandle)
	cert := Certificate{}
	dec := codec.NewDecoderBytes(rawCert, cborHandle)
	err := dec.Decode(&cert)
	if err != nil {
		return false, err
	}
	if len(cert.Signatures) != 1 {
		return false, errors.New("there must be one signature only")
	}
	mesg, err := cert.message()
	if err != nil {
		return false, err
	}
	if time.Unix(int64(cert.Expiration*hourSeconds), 0).Before(time.Now()) {
		return false, errors.New("certificate expired")
	}
	return publicKey.Verify(cert.Signatures[0].Payload, mesg), nil
}

// VerifyMulti is used to verify one of the signatures attached to the certificate.
func VerifyMulti(rawCert []byte, publicKey *eddsa.PublicKey) (bool, error) {
	cborHandle := new(codec.CborHandle)
	cert := new(Certificate)
	enc := codec.NewDecoderBytes(rawCert, cborHandle)
	err := enc.Decode(cert)
	if err != nil {
		return false, err
	}
	if time.Unix(int64(cert.Expiration*hourSeconds), 0).Before(time.Now()) {
		return false, errors.New("certificate expired")
	}
	for _, sig := range cert.Signatures {
		if bytes.Equal(publicKey.Bytes(), sig.Identity) {
			mesg, err := cert.message()
			if err != nil {
				return false, err
			}
			return publicKey.Verify(sig.Payload, mesg), nil
		}
	}
	return false, nil
}

// SignMultiCertificate uses the given signing key to create a signature
// and appends it to the certificate and returns it.
func SignMultiCertificate(signingKey *eddsa.PrivateKey, rawCert []byte) ([]byte, error) {
	// decode certificate
	cborHandle := new(codec.CborHandle)
	cert := new(Certificate)
	dec := codec.NewDecoderBytes(rawCert, cborHandle)
	err := dec.Decode(cert)
	if err != nil {
		return nil, err
	}

	// sign the certificate's message contents
	mesg, err := cert.message()
	if err != nil {
		return nil, err
	}
	signature := Signature{
		Identity: signingKey.PublicKey().Bytes(),
		Payload:  signingKey.Sign(mesg),
	}
	cert.Signatures = append(cert.Signatures, signature)

	// serialize certificate
	out := []byte{}
	enc := codec.NewEncoderBytes(&out, cborHandle)
	err = enc.Encode(&cert)
	if err != nil {
		return nil, err
	}
	return out, nil
}
