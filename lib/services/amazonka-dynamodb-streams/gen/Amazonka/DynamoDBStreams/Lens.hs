{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-warn-duplicate-exports #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}

-- Derived from AWS service descriptions, licensed under Apache 2.0.

-- |
-- Module      : Amazonka.DynamoDBStreams.Lens
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.DynamoDBStreams.Lens
  ( -- * Operations

    -- ** GetShardIterator
    getShardIterator_sequenceNumber,
    getShardIterator_streamArn,
    getShardIterator_shardId,
    getShardIterator_shardIteratorType,
    getShardIteratorResponse_shardIterator,
    getShardIteratorResponse_httpStatus,

    -- ** GetRecords
    getRecords_limit,
    getRecords_shardIterator,
    getRecordsResponse_records,
    getRecordsResponse_nextShardIterator,
    getRecordsResponse_httpStatus,

    -- ** ListStreams
    listStreams_exclusiveStartStreamArn,
    listStreams_limit,
    listStreams_tableName,
    listStreamsResponse_lastEvaluatedStreamArn,
    listStreamsResponse_streams,
    listStreamsResponse_httpStatus,

    -- ** DescribeStream
    describeStream_exclusiveStartShardId,
    describeStream_limit,
    describeStream_streamArn,
    describeStreamResponse_streamDescription,
    describeStreamResponse_httpStatus,

    -- * Types

    -- ** AttributeValue
    attributeValue_l,
    attributeValue_ns,
    attributeValue_m,
    attributeValue_null,
    attributeValue_n,
    attributeValue_bs,
    attributeValue_b,
    attributeValue_ss,
    attributeValue_s,
    attributeValue_bool,

    -- ** Identity
    identity_principalId,
    identity_type,

    -- ** KeySchemaElement
    keySchemaElement_attributeName,
    keySchemaElement_keyType,

    -- ** Record
    record_userIdentity,
    record_eventVersion,
    record_dynamodb,
    record_awsRegion,
    record_eventName,
    record_eventSource,
    record_eventID,

    -- ** SequenceNumberRange
    sequenceNumberRange_startingSequenceNumber,
    sequenceNumberRange_endingSequenceNumber,

    -- ** Shard
    shard_parentShardId,
    shard_sequenceNumberRange,
    shard_shardId,

    -- ** Stream
    stream_streamLabel,
    stream_streamArn,
    stream_tableName,

    -- ** StreamDescription
    streamDescription_lastEvaluatedShardId,
    streamDescription_streamLabel,
    streamDescription_streamStatus,
    streamDescription_keySchema,
    streamDescription_streamViewType,
    streamDescription_streamArn,
    streamDescription_shards,
    streamDescription_tableName,
    streamDescription_creationRequestDateTime,

    -- ** StreamRecord
    streamRecord_sizeBytes,
    streamRecord_sequenceNumber,
    streamRecord_approximateCreationDateTime,
    streamRecord_streamViewType,
    streamRecord_keys,
    streamRecord_oldImage,
    streamRecord_newImage,
  )
where

import Amazonka.DynamoDBStreams.DescribeStream
import Amazonka.DynamoDBStreams.GetRecords
import Amazonka.DynamoDBStreams.GetShardIterator
import Amazonka.DynamoDBStreams.ListStreams
import Amazonka.DynamoDBStreams.Types.AttributeValue
import Amazonka.DynamoDBStreams.Types.Identity
import Amazonka.DynamoDBStreams.Types.KeySchemaElement
import Amazonka.DynamoDBStreams.Types.Record
import Amazonka.DynamoDBStreams.Types.SequenceNumberRange
import Amazonka.DynamoDBStreams.Types.Shard
import Amazonka.DynamoDBStreams.Types.Stream
import Amazonka.DynamoDBStreams.Types.StreamDescription
import Amazonka.DynamoDBStreams.Types.StreamRecord
