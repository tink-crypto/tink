// Copyright 2020 Google LLC
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
//
///////////////////////////////////////////////////////////////////////////////

// Package services is implements gRPC services for testing_api.
package services

import (
	"bytes"
	"context"
	"errors"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/jwt"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/prf"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/streamingaead"
	"github.com/google/tink/go/testkeyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	pb "github.com/google/tink/testing/go/proto/testing_api_go_grpc"

	"google.golang.org/protobuf/proto"
)

// KeysetService implements the Keyset testing service.
type KeysetService struct {
	Templates map[string]*tinkpb.KeyTemplate
	pb.KeysetServer
}

func (s *KeysetService) GetTemplate(ctx context.Context, req *pb.KeysetTemplateRequest) (*pb.KeysetTemplateResponse, error) {
	if s.Templates == nil {
		s.Templates = map[string]*tinkpb.KeyTemplate{
			"AES128_GCM":                                                 aead.AES128GCMKeyTemplate(),
			"AES256_GCM":                                                 aead.AES256GCMKeyTemplate(),
			"AES256_GCM_RAW":                                             aead.AES256GCMNoPrefixKeyTemplate(),
			"AES128_CTR_HMAC_SHA256":                                     aead.AES128CTRHMACSHA256KeyTemplate(),
			"AES256_CTR_HMAC_SHA256":                                     aead.AES256CTRHMACSHA256KeyTemplate(),
			"CHACHA20_POLY1305":                                          aead.ChaCha20Poly1305KeyTemplate(),
			"XCHACHA20_POLY1305":                                         aead.XChaCha20Poly1305KeyTemplate(),
			"AES256_SIV":                                                 daead.AESSIVKeyTemplate(),
			"AES128_CTR_HMAC_SHA256_4KB":                                 streamingaead.AES128CTRHMACSHA256Segment4KBKeyTemplate(),
			"AES128_CTR_HMAC_SHA256_1MB":                                 streamingaead.AES128CTRHMACSHA256Segment1MBKeyTemplate(),
			"AES256_CTR_HMAC_SHA256_4KB":                                 streamingaead.AES256CTRHMACSHA256Segment4KBKeyTemplate(),
			"AES256_CTR_HMAC_SHA256_1MB":                                 streamingaead.AES256CTRHMACSHA256Segment1MBKeyTemplate(),
			"AES128_GCM_HKDF_4KB":                                        streamingaead.AES128GCMHKDF4KBKeyTemplate(),
			"AES128_GCM_HKDF_1MB":                                        streamingaead.AES128GCMHKDF1MBKeyTemplate(),
			"AES256_GCM_HKDF_4KB":                                        streamingaead.AES256GCMHKDF4KBKeyTemplate(),
			"AES256_GCM_HKDF_1MB":                                        streamingaead.AES256GCMHKDF1MBKeyTemplate(),
			"ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM":                     hybrid.ECIESHKDFAES128GCMKeyTemplate(),
			"ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256":         hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate(),
			"DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM":           hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template(),
			"DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW":       hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Raw_Key_Template(),
			"DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM":           hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Key_Template(),
			"DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW":       hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Raw_Key_Template(),
			"DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305":     hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Key_Template(),
			"DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_RAW": hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template(),
			"AES_CMAC":                     mac.AESCMACTag128KeyTemplate(),
			"HMAC_SHA256_128BITTAG":        mac.HMACSHA256Tag128KeyTemplate(),
			"HMAC_SHA256_256BITTAG":        mac.HMACSHA256Tag256KeyTemplate(),
			"HMAC_SHA512_256BITTAG":        mac.HMACSHA512Tag256KeyTemplate(),
			"HMAC_SHA512_512BITTAG":        mac.HMACSHA512Tag512KeyTemplate(),
			"ECDSA_P256":                   signature.ECDSAP256KeyTemplate(),
			"ECDSA_P256_RAW":               signature.ECDSAP256RawKeyTemplate(),
			"ECDSA_P384":                   signature.ECDSAP384KeyTemplate(),
			"ECDSA_P384_SHA384":            signature.ECDSAP384SHA384KeyTemplate(),
			"ECDSA_P384_SHA512":            signature.ECDSAP384SHA512KeyTemplate(),
			"ECDSA_P521":                   signature.ECDSAP521KeyTemplate(),
			"ED25519":                      signature.ED25519KeyTemplate(),
			"RSA_SSA_PKCS1_3072_SHA256_F4": signature.RSA_SSA_PKCS1_3072_SHA256_F4_Key_Template(),
			"RSA_SSA_PKCS1_4096_SHA512_F4": signature.RSA_SSA_PKCS1_4096_SHA512_F4_Key_Template(),
			"AES_CMAC_PRF":                 prf.AESCMACPRFKeyTemplate(),
			"HMAC_SHA256_PRF":              prf.HMACSHA256PRFKeyTemplate(),
			"HMAC_SHA512_PRF":              prf.HMACSHA512PRFKeyTemplate(),
			"HKDF_SHA256":                  prf.HKDFSHA256PRFKeyTemplate(),
			"JWT_HS256":                    jwt.HS256Template(),
			"JWT_HS256_RAW":                jwt.RawHS256Template(),
			"JWT_HS384":                    jwt.HS384Template(),
			"JWT_HS384_RAW":                jwt.RawHS384Template(),
			"JWT_HS512":                    jwt.HS512Template(),
			"JWT_HS512_RAW":                jwt.RawHS512Template(),
			"JWT_ES256":                    jwt.ES256Template(),
			"JWT_ES256_RAW":                jwt.RawES256Template(),
			"JWT_ES384":                    jwt.ES384Template(),
			"JWT_ES384_RAW":                jwt.RawES384Template(),
			"JWT_ES512":                    jwt.ES512Template(),
			"JWT_ES512_RAW":                jwt.RawES512Template(),
		}
	}
	template, success := s.Templates[req.GetTemplateName()]
	if success && template != nil {
		d, err := proto.Marshal(template)
		if err != nil {
			return &pb.KeysetTemplateResponse{
				Result: &pb.KeysetTemplateResponse_Err{err.Error()}}, nil
		}
		return &pb.KeysetTemplateResponse{
			Result: &pb.KeysetTemplateResponse_KeyTemplate{d}}, nil
	}
	return &pb.KeysetTemplateResponse{
		Result: &pb.KeysetTemplateResponse_Err{"key template not found"}}, nil
}

func (s *KeysetService) Generate(ctx context.Context, req *pb.KeysetGenerateRequest) (*pb.KeysetGenerateResponse, error) {
	template := &tinkpb.KeyTemplate{}
	err := proto.Unmarshal(req.Template, template)
	if err != nil {
		return &pb.KeysetGenerateResponse{
			Result: &pb.KeysetGenerateResponse_Err{err.Error()}}, nil
	}
	handle, err := keyset.NewHandle(template)
	if err != nil {
		return &pb.KeysetGenerateResponse{
			Result: &pb.KeysetGenerateResponse_Err{err.Error()}}, nil
	}
	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	err = testkeyset.Write(handle, writer)
	if err != nil {
		return &pb.KeysetGenerateResponse{
			Result: &pb.KeysetGenerateResponse_Err{err.Error()}}, nil
	}
	return &pb.KeysetGenerateResponse{
		Result: &pb.KeysetGenerateResponse_Keyset{buf.Bytes()}}, nil
}

func (s *KeysetService) Public(ctx context.Context, req *pb.KeysetPublicRequest) (*pb.KeysetPublicResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.PrivateKeyset))
	privateHandle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.KeysetPublicResponse{
			Result: &pb.KeysetPublicResponse_Err{err.Error()}}, nil
	}
	publicHandle, err := privateHandle.Public()
	if err != nil {
		return &pb.KeysetPublicResponse{
			Result: &pb.KeysetPublicResponse_Err{err.Error()}}, nil
	}
	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	err = testkeyset.Write(publicHandle, writer)
	if err != nil {
		return &pb.KeysetPublicResponse{
			Result: &pb.KeysetPublicResponse_Err{err.Error()}}, nil
	}
	return &pb.KeysetPublicResponse{
		Result: &pb.KeysetPublicResponse_PublicKeyset{buf.Bytes()}}, nil
}

func (s *KeysetService) ToJson(ctx context.Context, req *pb.KeysetToJsonRequest) (*pb.KeysetToJsonResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.KeysetToJsonResponse{
			Result: &pb.KeysetToJsonResponse_Err{err.Error()}}, nil
	}
	buf := new(bytes.Buffer)
	writer := keyset.NewJSONWriter(buf)
	if err := testkeyset.Write(handle, writer); err != nil {
		return &pb.KeysetToJsonResponse{
			Result: &pb.KeysetToJsonResponse_Err{err.Error()}}, nil
	}
	return &pb.KeysetToJsonResponse{
		Result: &pb.KeysetToJsonResponse_JsonKeyset{buf.String()}}, nil
}

func (s *KeysetService) FromJson(ctx context.Context, req *pb.KeysetFromJsonRequest) (*pb.KeysetFromJsonResponse, error) {
	reader := keyset.NewJSONReader(bytes.NewBufferString(req.JsonKeyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.KeysetFromJsonResponse{
			Result: &pb.KeysetFromJsonResponse_Err{err.Error()}}, nil
	}
	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	if err := testkeyset.Write(handle, writer); err != nil {
		return &pb.KeysetFromJsonResponse{
			Result: &pb.KeysetFromJsonResponse_Err{err.Error()}}, nil
	}
	return &pb.KeysetFromJsonResponse{
		Result: &pb.KeysetFromJsonResponse_Keyset{buf.Bytes()}}, nil
}

func (s *KeysetService) WriteEncrypted(ctx context.Context, req *pb.KeysetWriteEncryptedRequest) (*pb.KeysetWriteEncryptedResponse, error) {
	masterReader := keyset.NewBinaryReader(bytes.NewReader(req.GetMasterKeyset()))
	masterHandle, err := testkeyset.Read(masterReader)
	if err != nil {
		return &pb.KeysetWriteEncryptedResponse{
			Result: &pb.KeysetWriteEncryptedResponse_Err{err.Error()}}, nil
	}
	masterAead, err := aead.New(masterHandle)
	if err != nil {
		return &pb.KeysetWriteEncryptedResponse{
			Result: &pb.KeysetWriteEncryptedResponse_Err{err.Error()}}, nil
	}

	reader := keyset.NewBinaryReader(bytes.NewReader(req.GetKeyset()))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.KeysetWriteEncryptedResponse{
			Result: &pb.KeysetWriteEncryptedResponse_Err{err.Error()}}, nil
	}

	buf := new(bytes.Buffer)
	var writer keyset.Writer
	if req.GetKeysetWriterType() == pb.KeysetWriterType_KEYSET_WRITER_BINARY {
		writer = keyset.NewBinaryWriter(buf)
	} else if req.GetKeysetWriterType() == pb.KeysetWriterType_KEYSET_WRITER_JSON {
		writer = keyset.NewJSONWriter(buf)
	} else {
		return nil, errors.New("unknown keyset writer type")
	}
	if req.GetAssociatedData() != nil {
		err = handle.WriteWithAssociatedData(writer, masterAead, req.GetAssociatedData().GetValue())
	} else {
		err = handle.Write(writer, masterAead)
	}
	if err != nil {
		return &pb.KeysetWriteEncryptedResponse{
			Result: &pb.KeysetWriteEncryptedResponse_Err{err.Error()}}, nil
	}
	return &pb.KeysetWriteEncryptedResponse{
		Result: &pb.KeysetWriteEncryptedResponse_EncryptedKeyset{buf.Bytes()}}, nil
}

func (s *KeysetService) ReadEncrypted(ctx context.Context, req *pb.KeysetReadEncryptedRequest) (*pb.KeysetReadEncryptedResponse, error) {
	masterReader := keyset.NewBinaryReader(bytes.NewReader(req.GetMasterKeyset()))
	masterHandle, err := testkeyset.Read(masterReader)
	if err != nil {
		return &pb.KeysetReadEncryptedResponse{
			Result: &pb.KeysetReadEncryptedResponse_Err{err.Error()}}, nil
	}
	masterAead, err := aead.New(masterHandle)
	if err != nil {
		return &pb.KeysetReadEncryptedResponse{
			Result: &pb.KeysetReadEncryptedResponse_Err{err.Error()}}, nil
	}

	var reader keyset.Reader
	if req.GetKeysetReaderType() == pb.KeysetReaderType_KEYSET_READER_BINARY {
		reader = keyset.NewBinaryReader(bytes.NewReader(req.GetEncryptedKeyset()))
	} else if req.GetKeysetReaderType() == pb.KeysetReaderType_KEYSET_READER_JSON {
		reader = keyset.NewJSONReader(bytes.NewReader(req.GetEncryptedKeyset()))
	} else {
		return nil, errors.New("unknown keyset reader type")
	}
	var handle *keyset.Handle
	if req.GetAssociatedData() != nil {
		handle, err = keyset.ReadWithAssociatedData(reader, masterAead, req.GetAssociatedData().GetValue())
	} else {
		handle, err = keyset.Read(reader, masterAead)
	}
	if err != nil {
		return &pb.KeysetReadEncryptedResponse{
			Result: &pb.KeysetReadEncryptedResponse_Err{err.Error()}}, nil
	}

	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	if err := testkeyset.Write(handle, writer); err != nil {
		return &pb.KeysetReadEncryptedResponse{
			Result: &pb.KeysetReadEncryptedResponse_Err{err.Error()}}, nil
	}
	return &pb.KeysetReadEncryptedResponse{
		Result: &pb.KeysetReadEncryptedResponse_Keyset{buf.Bytes()}}, nil
}
