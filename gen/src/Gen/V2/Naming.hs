{-# LANGUAGE OverloadedStrings #-}

-- Module      : Gen.V2.Naming
-- Copyright   : (c) 2013-2014 Brendan Hay <brendan.g.hay@gmail.com>
-- License     : This Source Code Form is subject to the terms of
--               the Mozilla Public License, v. 2.0.
--               A copy of the MPL can be found in the LICENSE file or
--               you can obtain it at http://mozilla.org/MPL/2.0/.
-- Maintainer  : Brendan Hay <brendan.g.hay@gmail.com>
-- Stability   : experimental
-- Portability : non-portable (GHC extensions)

module Gen.V2.Naming where

import           Data.Char
import           Data.Maybe
import           Data.Text            (Text)
import qualified Data.Text            as Text
import           Data.Text.Manipulate

lensName :: Text -> Text
lensName = stripText "_"

keyPython :: Text -> Text
keyPython = toSnake . keyName . Text.replace "." "_"

keyName :: Text -> Text
keyName t
    | "_" `Text.isPrefixOf` t = lowerHead (dropLower t)
    | otherwise               = t

dropLower :: Text -> Text
dropLower = Text.dropWhile (not . isUpper)

stripAWS :: Text -> Text
stripAWS = stripText "Amazon" . stripText "AWS" . Text.replace " " ""

stripText :: Text -> Text -> Text
stripText p t = fromMaybe t (p `Text.stripPrefix` t)

