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
-- Module      : Amazonka.WorkSpacesWeb.CreateTrustStore
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Creates a trust store that can be associated with a web portal. A trust
-- store contains certificate authority (CA) certificates. Once associated
-- with a web portal, the browser in a streaming session will recognize
-- certificates that have been issued using any of the CAs in the trust
-- store. If your organization has internal websites that use certificates
-- issued by private CAs, you should add the private CA certificate to the
-- trust store.
module Amazonka.WorkSpacesWeb.CreateTrustStore
  ( -- * Creating a Request
    CreateTrustStore (..),
    newCreateTrustStore,

    -- * Request Lenses
    createTrustStore_tags,
    createTrustStore_clientToken,
    createTrustStore_certificateList,

    -- * Destructuring the Response
    CreateTrustStoreResponse (..),
    newCreateTrustStoreResponse,

    -- * Response Lenses
    createTrustStoreResponse_httpStatus,
    createTrustStoreResponse_trustStoreArn,
  )
where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude
import qualified Amazonka.Request as Request
import qualified Amazonka.Response as Response
import Amazonka.WorkSpacesWeb.Types

-- | /See:/ 'newCreateTrustStore' smart constructor.
data CreateTrustStore = CreateTrustStore'
  { -- | The tags to add to the trust store. A tag is a key-value pair.
    tags :: Prelude.Maybe [Core.Sensitive Tag],
    -- | A unique, case-sensitive identifier that you provide to ensure the
    -- idempotency of the request. Idempotency ensures that an API request
    -- completes only once. With an idempotent request, if the original request
    -- completes successfully, subsequent retries with the same client token
    -- returns the result from the original successful request.
    --
    -- If you do not specify a client token, one is automatically generated by
    -- the AWS SDK.
    clientToken :: Prelude.Maybe Prelude.Text,
    -- | A list of CA certificates to be added to the trust store.
    certificateList :: [Core.Base64]
  }
  deriving (Prelude.Eq, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'CreateTrustStore' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'tags', 'createTrustStore_tags' - The tags to add to the trust store. A tag is a key-value pair.
--
-- 'clientToken', 'createTrustStore_clientToken' - A unique, case-sensitive identifier that you provide to ensure the
-- idempotency of the request. Idempotency ensures that an API request
-- completes only once. With an idempotent request, if the original request
-- completes successfully, subsequent retries with the same client token
-- returns the result from the original successful request.
--
-- If you do not specify a client token, one is automatically generated by
-- the AWS SDK.
--
-- 'certificateList', 'createTrustStore_certificateList' - A list of CA certificates to be added to the trust store.
newCreateTrustStore ::
  CreateTrustStore
newCreateTrustStore =
  CreateTrustStore'
    { tags = Prelude.Nothing,
      clientToken = Prelude.Nothing,
      certificateList = Prelude.mempty
    }

-- | The tags to add to the trust store. A tag is a key-value pair.
createTrustStore_tags :: Lens.Lens' CreateTrustStore (Prelude.Maybe [Tag])
createTrustStore_tags = Lens.lens (\CreateTrustStore' {tags} -> tags) (\s@CreateTrustStore' {} a -> s {tags = a} :: CreateTrustStore) Prelude.. Lens.mapping Lens.coerced

-- | A unique, case-sensitive identifier that you provide to ensure the
-- idempotency of the request. Idempotency ensures that an API request
-- completes only once. With an idempotent request, if the original request
-- completes successfully, subsequent retries with the same client token
-- returns the result from the original successful request.
--
-- If you do not specify a client token, one is automatically generated by
-- the AWS SDK.
createTrustStore_clientToken :: Lens.Lens' CreateTrustStore (Prelude.Maybe Prelude.Text)
createTrustStore_clientToken = Lens.lens (\CreateTrustStore' {clientToken} -> clientToken) (\s@CreateTrustStore' {} a -> s {clientToken = a} :: CreateTrustStore)

-- | A list of CA certificates to be added to the trust store.
createTrustStore_certificateList :: Lens.Lens' CreateTrustStore [Prelude.ByteString]
createTrustStore_certificateList = Lens.lens (\CreateTrustStore' {certificateList} -> certificateList) (\s@CreateTrustStore' {} a -> s {certificateList = a} :: CreateTrustStore) Prelude.. Lens.coerced

instance Core.AWSRequest CreateTrustStore where
  type
    AWSResponse CreateTrustStore =
      CreateTrustStoreResponse
  request = Request.postJSON defaultService
  response =
    Response.receiveJSON
      ( \s h x ->
          CreateTrustStoreResponse'
            Prelude.<$> (Prelude.pure (Prelude.fromEnum s))
            Prelude.<*> (x Core..:> "trustStoreArn")
      )

instance Prelude.Hashable CreateTrustStore where
  hashWithSalt _salt CreateTrustStore' {..} =
    _salt `Prelude.hashWithSalt` tags
      `Prelude.hashWithSalt` clientToken
      `Prelude.hashWithSalt` certificateList

instance Prelude.NFData CreateTrustStore where
  rnf CreateTrustStore' {..} =
    Prelude.rnf tags
      `Prelude.seq` Prelude.rnf clientToken
      `Prelude.seq` Prelude.rnf certificateList

instance Core.ToHeaders CreateTrustStore where
  toHeaders =
    Prelude.const
      ( Prelude.mconcat
          [ "Content-Type"
              Core.=# ( "application/x-amz-json-1.1" ::
                          Prelude.ByteString
                      )
          ]
      )

instance Core.ToJSON CreateTrustStore where
  toJSON CreateTrustStore' {..} =
    Core.object
      ( Prelude.catMaybes
          [ ("tags" Core..=) Prelude.<$> tags,
            ("clientToken" Core..=) Prelude.<$> clientToken,
            Prelude.Just
              ("certificateList" Core..= certificateList)
          ]
      )

instance Core.ToPath CreateTrustStore where
  toPath = Prelude.const "/trustStores"

instance Core.ToQuery CreateTrustStore where
  toQuery = Prelude.const Prelude.mempty

-- | /See:/ 'newCreateTrustStoreResponse' smart constructor.
data CreateTrustStoreResponse = CreateTrustStoreResponse'
  { -- | The response's http status code.
    httpStatus :: Prelude.Int,
    -- | The ARN of the trust store.
    trustStoreArn :: Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'CreateTrustStoreResponse' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'httpStatus', 'createTrustStoreResponse_httpStatus' - The response's http status code.
--
-- 'trustStoreArn', 'createTrustStoreResponse_trustStoreArn' - The ARN of the trust store.
newCreateTrustStoreResponse ::
  -- | 'httpStatus'
  Prelude.Int ->
  -- | 'trustStoreArn'
  Prelude.Text ->
  CreateTrustStoreResponse
newCreateTrustStoreResponse
  pHttpStatus_
  pTrustStoreArn_ =
    CreateTrustStoreResponse'
      { httpStatus =
          pHttpStatus_,
        trustStoreArn = pTrustStoreArn_
      }

-- | The response's http status code.
createTrustStoreResponse_httpStatus :: Lens.Lens' CreateTrustStoreResponse Prelude.Int
createTrustStoreResponse_httpStatus = Lens.lens (\CreateTrustStoreResponse' {httpStatus} -> httpStatus) (\s@CreateTrustStoreResponse' {} a -> s {httpStatus = a} :: CreateTrustStoreResponse)

-- | The ARN of the trust store.
createTrustStoreResponse_trustStoreArn :: Lens.Lens' CreateTrustStoreResponse Prelude.Text
createTrustStoreResponse_trustStoreArn = Lens.lens (\CreateTrustStoreResponse' {trustStoreArn} -> trustStoreArn) (\s@CreateTrustStoreResponse' {} a -> s {trustStoreArn = a} :: CreateTrustStoreResponse)

instance Prelude.NFData CreateTrustStoreResponse where
  rnf CreateTrustStoreResponse' {..} =
    Prelude.rnf httpStatus
      `Prelude.seq` Prelude.rnf trustStoreArn
