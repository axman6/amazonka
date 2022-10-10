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
-- Module      : Amazonka.WorkSpacesWeb.UpdateTrustStore
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Updates the trust store.
module Amazonka.WorkSpacesWeb.UpdateTrustStore
  ( -- * Creating a Request
    UpdateTrustStore (..),
    newUpdateTrustStore,

    -- * Request Lenses
    updateTrustStore_certificatesToAdd,
    updateTrustStore_clientToken,
    updateTrustStore_certificatesToDelete,
    updateTrustStore_trustStoreArn,

    -- * Destructuring the Response
    UpdateTrustStoreResponse (..),
    newUpdateTrustStoreResponse,

    -- * Response Lenses
    updateTrustStoreResponse_httpStatus,
    updateTrustStoreResponse_trustStoreArn,
  )
where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude
import qualified Amazonka.Request as Request
import qualified Amazonka.Response as Response
import Amazonka.WorkSpacesWeb.Types

-- | /See:/ 'newUpdateTrustStore' smart constructor.
data UpdateTrustStore = UpdateTrustStore'
  { -- | A list of CA certificates to add to the trust store.
    certificatesToAdd :: Prelude.Maybe [Core.Base64],
    -- | A unique, case-sensitive identifier that you provide to ensure the
    -- idempotency of the request. Idempotency ensures that an API request
    -- completes only once. With an idempotent request, if the original request
    -- completes successfully, subsequent retries with the same client token
    -- return the result from the original successful request.
    --
    -- If you do not specify a client token, one is automatically generated by
    -- the AWS SDK.
    clientToken :: Prelude.Maybe Prelude.Text,
    -- | A list of CA certificates to delete from a trust store.
    certificatesToDelete :: Prelude.Maybe [Prelude.Text],
    -- | The ARN of the trust store.
    trustStoreArn :: Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'UpdateTrustStore' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'certificatesToAdd', 'updateTrustStore_certificatesToAdd' - A list of CA certificates to add to the trust store.
--
-- 'clientToken', 'updateTrustStore_clientToken' - A unique, case-sensitive identifier that you provide to ensure the
-- idempotency of the request. Idempotency ensures that an API request
-- completes only once. With an idempotent request, if the original request
-- completes successfully, subsequent retries with the same client token
-- return the result from the original successful request.
--
-- If you do not specify a client token, one is automatically generated by
-- the AWS SDK.
--
-- 'certificatesToDelete', 'updateTrustStore_certificatesToDelete' - A list of CA certificates to delete from a trust store.
--
-- 'trustStoreArn', 'updateTrustStore_trustStoreArn' - The ARN of the trust store.
newUpdateTrustStore ::
  -- | 'trustStoreArn'
  Prelude.Text ->
  UpdateTrustStore
newUpdateTrustStore pTrustStoreArn_ =
  UpdateTrustStore'
    { certificatesToAdd =
        Prelude.Nothing,
      clientToken = Prelude.Nothing,
      certificatesToDelete = Prelude.Nothing,
      trustStoreArn = pTrustStoreArn_
    }

-- | A list of CA certificates to add to the trust store.
updateTrustStore_certificatesToAdd :: Lens.Lens' UpdateTrustStore (Prelude.Maybe [Prelude.ByteString])
updateTrustStore_certificatesToAdd = Lens.lens (\UpdateTrustStore' {certificatesToAdd} -> certificatesToAdd) (\s@UpdateTrustStore' {} a -> s {certificatesToAdd = a} :: UpdateTrustStore) Prelude.. Lens.mapping Lens.coerced

-- | A unique, case-sensitive identifier that you provide to ensure the
-- idempotency of the request. Idempotency ensures that an API request
-- completes only once. With an idempotent request, if the original request
-- completes successfully, subsequent retries with the same client token
-- return the result from the original successful request.
--
-- If you do not specify a client token, one is automatically generated by
-- the AWS SDK.
updateTrustStore_clientToken :: Lens.Lens' UpdateTrustStore (Prelude.Maybe Prelude.Text)
updateTrustStore_clientToken = Lens.lens (\UpdateTrustStore' {clientToken} -> clientToken) (\s@UpdateTrustStore' {} a -> s {clientToken = a} :: UpdateTrustStore)

-- | A list of CA certificates to delete from a trust store.
updateTrustStore_certificatesToDelete :: Lens.Lens' UpdateTrustStore (Prelude.Maybe [Prelude.Text])
updateTrustStore_certificatesToDelete = Lens.lens (\UpdateTrustStore' {certificatesToDelete} -> certificatesToDelete) (\s@UpdateTrustStore' {} a -> s {certificatesToDelete = a} :: UpdateTrustStore) Prelude.. Lens.mapping Lens.coerced

-- | The ARN of the trust store.
updateTrustStore_trustStoreArn :: Lens.Lens' UpdateTrustStore Prelude.Text
updateTrustStore_trustStoreArn = Lens.lens (\UpdateTrustStore' {trustStoreArn} -> trustStoreArn) (\s@UpdateTrustStore' {} a -> s {trustStoreArn = a} :: UpdateTrustStore)

instance Core.AWSRequest UpdateTrustStore where
  type
    AWSResponse UpdateTrustStore =
      UpdateTrustStoreResponse
  request = Request.patchJSON defaultService
  response =
    Response.receiveJSON
      ( \s h x ->
          UpdateTrustStoreResponse'
            Prelude.<$> (Prelude.pure (Prelude.fromEnum s))
            Prelude.<*> (x Core..:> "trustStoreArn")
      )

instance Prelude.Hashable UpdateTrustStore where
  hashWithSalt _salt UpdateTrustStore' {..} =
    _salt `Prelude.hashWithSalt` certificatesToAdd
      `Prelude.hashWithSalt` clientToken
      `Prelude.hashWithSalt` certificatesToDelete
      `Prelude.hashWithSalt` trustStoreArn

instance Prelude.NFData UpdateTrustStore where
  rnf UpdateTrustStore' {..} =
    Prelude.rnf certificatesToAdd
      `Prelude.seq` Prelude.rnf clientToken
      `Prelude.seq` Prelude.rnf certificatesToDelete
      `Prelude.seq` Prelude.rnf trustStoreArn

instance Core.ToHeaders UpdateTrustStore where
  toHeaders =
    Prelude.const
      ( Prelude.mconcat
          [ "Content-Type"
              Core.=# ( "application/x-amz-json-1.1" ::
                          Prelude.ByteString
                      )
          ]
      )

instance Core.ToJSON UpdateTrustStore where
  toJSON UpdateTrustStore' {..} =
    Core.object
      ( Prelude.catMaybes
          [ ("certificatesToAdd" Core..=)
              Prelude.<$> certificatesToAdd,
            ("clientToken" Core..=) Prelude.<$> clientToken,
            ("certificatesToDelete" Core..=)
              Prelude.<$> certificatesToDelete
          ]
      )

instance Core.ToPath UpdateTrustStore where
  toPath UpdateTrustStore' {..} =
    Prelude.mconcat
      ["/trustStores/", Core.toBS trustStoreArn]

instance Core.ToQuery UpdateTrustStore where
  toQuery = Prelude.const Prelude.mempty

-- | /See:/ 'newUpdateTrustStoreResponse' smart constructor.
data UpdateTrustStoreResponse = UpdateTrustStoreResponse'
  { -- | The response's http status code.
    httpStatus :: Prelude.Int,
    -- | The ARN of the trust store.
    trustStoreArn :: Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'UpdateTrustStoreResponse' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'httpStatus', 'updateTrustStoreResponse_httpStatus' - The response's http status code.
--
-- 'trustStoreArn', 'updateTrustStoreResponse_trustStoreArn' - The ARN of the trust store.
newUpdateTrustStoreResponse ::
  -- | 'httpStatus'
  Prelude.Int ->
  -- | 'trustStoreArn'
  Prelude.Text ->
  UpdateTrustStoreResponse
newUpdateTrustStoreResponse
  pHttpStatus_
  pTrustStoreArn_ =
    UpdateTrustStoreResponse'
      { httpStatus =
          pHttpStatus_,
        trustStoreArn = pTrustStoreArn_
      }

-- | The response's http status code.
updateTrustStoreResponse_httpStatus :: Lens.Lens' UpdateTrustStoreResponse Prelude.Int
updateTrustStoreResponse_httpStatus = Lens.lens (\UpdateTrustStoreResponse' {httpStatus} -> httpStatus) (\s@UpdateTrustStoreResponse' {} a -> s {httpStatus = a} :: UpdateTrustStoreResponse)

-- | The ARN of the trust store.
updateTrustStoreResponse_trustStoreArn :: Lens.Lens' UpdateTrustStoreResponse Prelude.Text
updateTrustStoreResponse_trustStoreArn = Lens.lens (\UpdateTrustStoreResponse' {trustStoreArn} -> trustStoreArn) (\s@UpdateTrustStoreResponse' {} a -> s {trustStoreArn = a} :: UpdateTrustStoreResponse)

instance Prelude.NFData UpdateTrustStoreResponse where
  rnf UpdateTrustStoreResponse' {..} =
    Prelude.rnf httpStatus
      `Prelude.seq` Prelude.rnf trustStoreArn
