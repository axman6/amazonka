{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-warn-unused-binds #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}
{-# OPTIONS_GHC -fno-warn-unused-matches #-}

-- Derived from AWS service descriptions, licensed under Apache 2.0.

-- |
-- Module      : Amazonka.KMS.Verify
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Verifies a digital signature that was generated by the Sign operation.
--
-- Verification confirms that an authorized user signed the message with
-- the specified KMS key and signing algorithm, and the message hasn\'t
-- changed since it was signed. If the signature is verified, the value of
-- the @SignatureValid@ field in the response is @True@. If the signature
-- verification fails, the @Verify@ operation fails with an
-- @KMSInvalidSignatureException@ exception.
--
-- A digital signature is generated by using the private key in an
-- asymmetric KMS key. The signature is verified by using the public key in
-- the same asymmetric KMS key. For information about asymmetric KMS keys,
-- see
-- <https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html Asymmetric KMS keys>
-- in the /Key Management Service Developer Guide/.
--
-- To verify a digital signature, you can use the @Verify@ operation.
-- Specify the same asymmetric KMS key, message, and signing algorithm that
-- were used to produce the signature.
--
-- You can also verify the digital signature by using the public key of the
-- KMS key outside of KMS. Use the GetPublicKey operation to download the
-- public key in the asymmetric KMS key and then use the public key to
-- verify the signature outside of KMS. To verify a signature outside of
-- KMS with an SM2 public key, you must specify the distinguishing ID. By
-- default, KMS uses @1234567812345678@ as the distinguishing ID. For more
-- information, see
-- <https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html#key-spec-sm-offline-verification Offline verification with SM2 key pairs>
-- in /Key Management Service Developer Guide/. The advantage of using the
-- @Verify@ operation is that it is performed within KMS. As a result,
-- it\'s easy to call, the operation is performed within the FIPS boundary,
-- it is logged in CloudTrail, and you can use key policy and IAM policy to
-- determine who is authorized to use the KMS key to verify signatures.
--
-- The KMS key that you use for this operation must be in a compatible key
-- state. For details, see
-- <https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html Key states of KMS keys>
-- in the /Key Management Service Developer Guide/.
--
-- __Cross-account use__: Yes. To perform this operation with a KMS key in
-- a different Amazon Web Services account, specify the key ARN or alias
-- ARN in the value of the @KeyId@ parameter.
--
-- __Required permissions__:
-- <https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html kms:Verify>
-- (key policy)
--
-- __Related operations__: Sign
module Amazonka.KMS.Verify
  ( -- * Creating a Request
    Verify (..),
    newVerify,

    -- * Request Lenses
    verify_messageType,
    verify_grantTokens,
    verify_keyId,
    verify_message,
    verify_signature,
    verify_signingAlgorithm,

    -- * Destructuring the Response
    VerifyResponse (..),
    newVerifyResponse,

    -- * Response Lenses
    verifyResponse_signatureValid,
    verifyResponse_signingAlgorithm,
    verifyResponse_keyId,
    verifyResponse_httpStatus,
  )
where

import qualified Amazonka.Core as Core
import qualified Amazonka.Core.Lens.Internal as Lens
import Amazonka.KMS.Types
import qualified Amazonka.Prelude as Prelude
import qualified Amazonka.Request as Request
import qualified Amazonka.Response as Response

-- | /See:/ 'newVerify' smart constructor.
data Verify = Verify'
  { -- | Tells KMS whether the value of the @Message@ parameter is a message or
    -- message digest. The default value, RAW, indicates a message. To indicate
    -- a message digest, enter @DIGEST@.
    --
    -- Use the @DIGEST@ value only when the value of the @Message@ parameter is
    -- a message digest. If you use the @DIGEST@ value with a raw message, the
    -- security of the verification operation can be compromised.
    messageType :: Prelude.Maybe MessageType,
    -- | A list of grant tokens.
    --
    -- Use a grant token when your permission to call this operation comes from
    -- a new grant that has not yet achieved /eventual consistency/. For more
    -- information, see
    -- <https://docs.aws.amazon.com/kms/latest/developerguide/grants.html#grant_token Grant token>
    -- and
    -- <https://docs.aws.amazon.com/kms/latest/developerguide/grant-manage.html#using-grant-token Using a grant token>
    -- in the /Key Management Service Developer Guide/.
    grantTokens :: Prelude.Maybe [Prelude.Text],
    -- | Identifies the asymmetric KMS key that will be used to verify the
    -- signature. This must be the same KMS key that was used to generate the
    -- signature. If you specify a different KMS key, the signature
    -- verification fails.
    --
    -- To specify a KMS key, use its key ID, key ARN, alias name, or alias ARN.
    -- When using an alias name, prefix it with @\"alias\/\"@. To specify a KMS
    -- key in a different Amazon Web Services account, you must use the key ARN
    -- or alias ARN.
    --
    -- For example:
    --
    -- -   Key ID: @1234abcd-12ab-34cd-56ef-1234567890ab@
    --
    -- -   Key ARN:
    --     @arn:aws:kms:us-east-2:111122223333:key\/1234abcd-12ab-34cd-56ef-1234567890ab@
    --
    -- -   Alias name: @alias\/ExampleAlias@
    --
    -- -   Alias ARN: @arn:aws:kms:us-east-2:111122223333:alias\/ExampleAlias@
    --
    -- To get the key ID and key ARN for a KMS key, use ListKeys or
    -- DescribeKey. To get the alias name and alias ARN, use ListAliases.
    keyId :: Prelude.Text,
    -- | Specifies the message that was signed. You can submit a raw message of
    -- up to 4096 bytes, or a hash digest of the message. If you submit a
    -- digest, use the @MessageType@ parameter with a value of @DIGEST@.
    --
    -- If the message specified here is different from the message that was
    -- signed, the signature verification fails. A message and its hash digest
    -- are considered to be the same message.
    message :: Core.Sensitive Core.Base64,
    -- | The signature that the @Sign@ operation generated.
    signature :: Core.Base64,
    -- | The signing algorithm that was used to sign the message. If you submit a
    -- different algorithm, the signature verification fails.
    signingAlgorithm :: SigningAlgorithmSpec
  }
  deriving (Prelude.Eq, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'Verify' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'messageType', 'verify_messageType' - Tells KMS whether the value of the @Message@ parameter is a message or
-- message digest. The default value, RAW, indicates a message. To indicate
-- a message digest, enter @DIGEST@.
--
-- Use the @DIGEST@ value only when the value of the @Message@ parameter is
-- a message digest. If you use the @DIGEST@ value with a raw message, the
-- security of the verification operation can be compromised.
--
-- 'grantTokens', 'verify_grantTokens' - A list of grant tokens.
--
-- Use a grant token when your permission to call this operation comes from
-- a new grant that has not yet achieved /eventual consistency/. For more
-- information, see
-- <https://docs.aws.amazon.com/kms/latest/developerguide/grants.html#grant_token Grant token>
-- and
-- <https://docs.aws.amazon.com/kms/latest/developerguide/grant-manage.html#using-grant-token Using a grant token>
-- in the /Key Management Service Developer Guide/.
--
-- 'keyId', 'verify_keyId' - Identifies the asymmetric KMS key that will be used to verify the
-- signature. This must be the same KMS key that was used to generate the
-- signature. If you specify a different KMS key, the signature
-- verification fails.
--
-- To specify a KMS key, use its key ID, key ARN, alias name, or alias ARN.
-- When using an alias name, prefix it with @\"alias\/\"@. To specify a KMS
-- key in a different Amazon Web Services account, you must use the key ARN
-- or alias ARN.
--
-- For example:
--
-- -   Key ID: @1234abcd-12ab-34cd-56ef-1234567890ab@
--
-- -   Key ARN:
--     @arn:aws:kms:us-east-2:111122223333:key\/1234abcd-12ab-34cd-56ef-1234567890ab@
--
-- -   Alias name: @alias\/ExampleAlias@
--
-- -   Alias ARN: @arn:aws:kms:us-east-2:111122223333:alias\/ExampleAlias@
--
-- To get the key ID and key ARN for a KMS key, use ListKeys or
-- DescribeKey. To get the alias name and alias ARN, use ListAliases.
--
-- 'message', 'verify_message' - Specifies the message that was signed. You can submit a raw message of
-- up to 4096 bytes, or a hash digest of the message. If you submit a
-- digest, use the @MessageType@ parameter with a value of @DIGEST@.
--
-- If the message specified here is different from the message that was
-- signed, the signature verification fails. A message and its hash digest
-- are considered to be the same message.--
-- -- /Note:/ This 'Lens' automatically encodes and decodes Base64 data.
-- -- The underlying isomorphism will encode to Base64 representation during
-- -- serialisation, and decode from Base64 representation during deserialisation.
-- -- This 'Lens' accepts and returns only raw unencoded data.
--
-- 'signature', 'verify_signature' - The signature that the @Sign@ operation generated.--
-- -- /Note:/ This 'Lens' automatically encodes and decodes Base64 data.
-- -- The underlying isomorphism will encode to Base64 representation during
-- -- serialisation, and decode from Base64 representation during deserialisation.
-- -- This 'Lens' accepts and returns only raw unencoded data.
--
-- 'signingAlgorithm', 'verify_signingAlgorithm' - The signing algorithm that was used to sign the message. If you submit a
-- different algorithm, the signature verification fails.
newVerify ::
  -- | 'keyId'
  Prelude.Text ->
  -- | 'message'
  Prelude.ByteString ->
  -- | 'signature'
  Prelude.ByteString ->
  -- | 'signingAlgorithm'
  SigningAlgorithmSpec ->
  Verify
newVerify
  pKeyId_
  pMessage_
  pSignature_
  pSigningAlgorithm_ =
    Verify'
      { messageType = Prelude.Nothing,
        grantTokens = Prelude.Nothing,
        keyId = pKeyId_,
        message =
          Core._Sensitive Prelude.. Core._Base64
            Lens.# pMessage_,
        signature = Core._Base64 Lens.# pSignature_,
        signingAlgorithm = pSigningAlgorithm_
      }

-- | Tells KMS whether the value of the @Message@ parameter is a message or
-- message digest. The default value, RAW, indicates a message. To indicate
-- a message digest, enter @DIGEST@.
--
-- Use the @DIGEST@ value only when the value of the @Message@ parameter is
-- a message digest. If you use the @DIGEST@ value with a raw message, the
-- security of the verification operation can be compromised.
verify_messageType :: Lens.Lens' Verify (Prelude.Maybe MessageType)
verify_messageType = Lens.lens (\Verify' {messageType} -> messageType) (\s@Verify' {} a -> s {messageType = a} :: Verify)

-- | A list of grant tokens.
--
-- Use a grant token when your permission to call this operation comes from
-- a new grant that has not yet achieved /eventual consistency/. For more
-- information, see
-- <https://docs.aws.amazon.com/kms/latest/developerguide/grants.html#grant_token Grant token>
-- and
-- <https://docs.aws.amazon.com/kms/latest/developerguide/grant-manage.html#using-grant-token Using a grant token>
-- in the /Key Management Service Developer Guide/.
verify_grantTokens :: Lens.Lens' Verify (Prelude.Maybe [Prelude.Text])
verify_grantTokens = Lens.lens (\Verify' {grantTokens} -> grantTokens) (\s@Verify' {} a -> s {grantTokens = a} :: Verify) Prelude.. Lens.mapping Lens.coerced

-- | Identifies the asymmetric KMS key that will be used to verify the
-- signature. This must be the same KMS key that was used to generate the
-- signature. If you specify a different KMS key, the signature
-- verification fails.
--
-- To specify a KMS key, use its key ID, key ARN, alias name, or alias ARN.
-- When using an alias name, prefix it with @\"alias\/\"@. To specify a KMS
-- key in a different Amazon Web Services account, you must use the key ARN
-- or alias ARN.
--
-- For example:
--
-- -   Key ID: @1234abcd-12ab-34cd-56ef-1234567890ab@
--
-- -   Key ARN:
--     @arn:aws:kms:us-east-2:111122223333:key\/1234abcd-12ab-34cd-56ef-1234567890ab@
--
-- -   Alias name: @alias\/ExampleAlias@
--
-- -   Alias ARN: @arn:aws:kms:us-east-2:111122223333:alias\/ExampleAlias@
--
-- To get the key ID and key ARN for a KMS key, use ListKeys or
-- DescribeKey. To get the alias name and alias ARN, use ListAliases.
verify_keyId :: Lens.Lens' Verify Prelude.Text
verify_keyId = Lens.lens (\Verify' {keyId} -> keyId) (\s@Verify' {} a -> s {keyId = a} :: Verify)

-- | Specifies the message that was signed. You can submit a raw message of
-- up to 4096 bytes, or a hash digest of the message. If you submit a
-- digest, use the @MessageType@ parameter with a value of @DIGEST@.
--
-- If the message specified here is different from the message that was
-- signed, the signature verification fails. A message and its hash digest
-- are considered to be the same message.--
-- -- /Note:/ This 'Lens' automatically encodes and decodes Base64 data.
-- -- The underlying isomorphism will encode to Base64 representation during
-- -- serialisation, and decode from Base64 representation during deserialisation.
-- -- This 'Lens' accepts and returns only raw unencoded data.
verify_message :: Lens.Lens' Verify Prelude.ByteString
verify_message = Lens.lens (\Verify' {message} -> message) (\s@Verify' {} a -> s {message = a} :: Verify) Prelude.. Core._Sensitive Prelude.. Core._Base64

-- | The signature that the @Sign@ operation generated.--
-- -- /Note:/ This 'Lens' automatically encodes and decodes Base64 data.
-- -- The underlying isomorphism will encode to Base64 representation during
-- -- serialisation, and decode from Base64 representation during deserialisation.
-- -- This 'Lens' accepts and returns only raw unencoded data.
verify_signature :: Lens.Lens' Verify Prelude.ByteString
verify_signature = Lens.lens (\Verify' {signature} -> signature) (\s@Verify' {} a -> s {signature = a} :: Verify) Prelude.. Core._Base64

-- | The signing algorithm that was used to sign the message. If you submit a
-- different algorithm, the signature verification fails.
verify_signingAlgorithm :: Lens.Lens' Verify SigningAlgorithmSpec
verify_signingAlgorithm = Lens.lens (\Verify' {signingAlgorithm} -> signingAlgorithm) (\s@Verify' {} a -> s {signingAlgorithm = a} :: Verify)

instance Core.AWSRequest Verify where
  type AWSResponse Verify = VerifyResponse
  request overrides =
    Request.postJSON (overrides defaultService)
  response =
    Response.receiveJSON
      ( \s h x ->
          VerifyResponse'
            Prelude.<$> (x Core..?> "SignatureValid")
            Prelude.<*> (x Core..?> "SigningAlgorithm")
            Prelude.<*> (x Core..?> "KeyId")
            Prelude.<*> (Prelude.pure (Prelude.fromEnum s))
      )

instance Prelude.Hashable Verify where
  hashWithSalt _salt Verify' {..} =
    _salt `Prelude.hashWithSalt` messageType
      `Prelude.hashWithSalt` grantTokens
      `Prelude.hashWithSalt` keyId
      `Prelude.hashWithSalt` message
      `Prelude.hashWithSalt` signature
      `Prelude.hashWithSalt` signingAlgorithm

instance Prelude.NFData Verify where
  rnf Verify' {..} =
    Prelude.rnf messageType
      `Prelude.seq` Prelude.rnf grantTokens
      `Prelude.seq` Prelude.rnf keyId
      `Prelude.seq` Prelude.rnf message
      `Prelude.seq` Prelude.rnf signature
      `Prelude.seq` Prelude.rnf signingAlgorithm

instance Core.ToHeaders Verify where
  toHeaders =
    Prelude.const
      ( Prelude.mconcat
          [ "X-Amz-Target"
              Core.=# ("TrentService.Verify" :: Prelude.ByteString),
            "Content-Type"
              Core.=# ( "application/x-amz-json-1.1" ::
                          Prelude.ByteString
                      )
          ]
      )

instance Core.ToJSON Verify where
  toJSON Verify' {..} =
    Core.object
      ( Prelude.catMaybes
          [ ("MessageType" Core..=) Prelude.<$> messageType,
            ("GrantTokens" Core..=) Prelude.<$> grantTokens,
            Prelude.Just ("KeyId" Core..= keyId),
            Prelude.Just ("Message" Core..= message),
            Prelude.Just ("Signature" Core..= signature),
            Prelude.Just
              ("SigningAlgorithm" Core..= signingAlgorithm)
          ]
      )

instance Core.ToPath Verify where
  toPath = Prelude.const "/"

instance Core.ToQuery Verify where
  toQuery = Prelude.const Prelude.mempty

-- | /See:/ 'newVerifyResponse' smart constructor.
data VerifyResponse = VerifyResponse'
  { -- | A Boolean value that indicates whether the signature was verified. A
    -- value of @True@ indicates that the @Signature@ was produced by signing
    -- the @Message@ with the specified @KeyID@ and @SigningAlgorithm.@ If the
    -- signature is not verified, the @Verify@ operation fails with a
    -- @KMSInvalidSignatureException@ exception.
    signatureValid :: Prelude.Maybe Prelude.Bool,
    -- | The signing algorithm that was used to verify the signature.
    signingAlgorithm :: Prelude.Maybe SigningAlgorithmSpec,
    -- | The Amazon Resource Name
    -- (<https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id-key-ARN key ARN>)
    -- of the asymmetric KMS key that was used to verify the signature.
    keyId :: Prelude.Maybe Prelude.Text,
    -- | The response's http status code.
    httpStatus :: Prelude.Int
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'VerifyResponse' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'signatureValid', 'verifyResponse_signatureValid' - A Boolean value that indicates whether the signature was verified. A
-- value of @True@ indicates that the @Signature@ was produced by signing
-- the @Message@ with the specified @KeyID@ and @SigningAlgorithm.@ If the
-- signature is not verified, the @Verify@ operation fails with a
-- @KMSInvalidSignatureException@ exception.
--
-- 'signingAlgorithm', 'verifyResponse_signingAlgorithm' - The signing algorithm that was used to verify the signature.
--
-- 'keyId', 'verifyResponse_keyId' - The Amazon Resource Name
-- (<https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id-key-ARN key ARN>)
-- of the asymmetric KMS key that was used to verify the signature.
--
-- 'httpStatus', 'verifyResponse_httpStatus' - The response's http status code.
newVerifyResponse ::
  -- | 'httpStatus'
  Prelude.Int ->
  VerifyResponse
newVerifyResponse pHttpStatus_ =
  VerifyResponse'
    { signatureValid = Prelude.Nothing,
      signingAlgorithm = Prelude.Nothing,
      keyId = Prelude.Nothing,
      httpStatus = pHttpStatus_
    }

-- | A Boolean value that indicates whether the signature was verified. A
-- value of @True@ indicates that the @Signature@ was produced by signing
-- the @Message@ with the specified @KeyID@ and @SigningAlgorithm.@ If the
-- signature is not verified, the @Verify@ operation fails with a
-- @KMSInvalidSignatureException@ exception.
verifyResponse_signatureValid :: Lens.Lens' VerifyResponse (Prelude.Maybe Prelude.Bool)
verifyResponse_signatureValid = Lens.lens (\VerifyResponse' {signatureValid} -> signatureValid) (\s@VerifyResponse' {} a -> s {signatureValid = a} :: VerifyResponse)

-- | The signing algorithm that was used to verify the signature.
verifyResponse_signingAlgorithm :: Lens.Lens' VerifyResponse (Prelude.Maybe SigningAlgorithmSpec)
verifyResponse_signingAlgorithm = Lens.lens (\VerifyResponse' {signingAlgorithm} -> signingAlgorithm) (\s@VerifyResponse' {} a -> s {signingAlgorithm = a} :: VerifyResponse)

-- | The Amazon Resource Name
-- (<https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id-key-ARN key ARN>)
-- of the asymmetric KMS key that was used to verify the signature.
verifyResponse_keyId :: Lens.Lens' VerifyResponse (Prelude.Maybe Prelude.Text)
verifyResponse_keyId = Lens.lens (\VerifyResponse' {keyId} -> keyId) (\s@VerifyResponse' {} a -> s {keyId = a} :: VerifyResponse)

-- | The response's http status code.
verifyResponse_httpStatus :: Lens.Lens' VerifyResponse Prelude.Int
verifyResponse_httpStatus = Lens.lens (\VerifyResponse' {httpStatus} -> httpStatus) (\s@VerifyResponse' {} a -> s {httpStatus = a} :: VerifyResponse)

instance Prelude.NFData VerifyResponse where
  rnf VerifyResponse' {..} =
    Prelude.rnf signatureValid
      `Prelude.seq` Prelude.rnf signingAlgorithm
      `Prelude.seq` Prelude.rnf keyId
      `Prelude.seq` Prelude.rnf httpStatus
