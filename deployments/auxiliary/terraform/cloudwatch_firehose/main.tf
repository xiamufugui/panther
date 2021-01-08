# Panther is a Cloud-Native SIEM for the Modern Security Team.
# Copyright (C) 2020 Panther Labs Inc
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Copyright (C) 2020 Panther Labs Inc
#
# Panther Enterprise is licensed under the terms of a commercial license available from
# Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
# All use, distribution, and/or modification of this software, whether commercial or non-commercial,
# falls under the Panther Commercial License to the extent it is permitted.



# Sample template for gathering Cloudwatch logs into S3 via Firehose.


### Cloudwatch Subsciption
resource "aws_cloudwatch_log_subscription_filter" "cloudwatch_log_filter" {
  name            = "cloudwatch_log_filter"
  role_arn        = aws_iam_role.cloudwatch_firehose_profile.arn
  log_group_name  = var.log_group_name
  filter_pattern  = "logtype cloudwatch"
  destination_arn = aws_kinesis_firehose_delivery_stream.cloudwatch_data_firehose.arn
  distribution    = "Random"
}

resource "aws_iam_role" "cloudwatch_firehose_profile" {
  name = "CloudwatchFirehoseAssumeRole-${var.aws_region}"

  assume_role_policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Principal : {
          Service : "firehose.amazonaws.com"
        },
        Action : "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role" "cloudwatch_firehose_write_only" {
  name = "CloudwatchFirehoseWriteOnly-${var.aws_region}"

  assume_role_policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Principal : {
          AWS : "arn:aws:iam::${var.aws_account_id}:root"
        },
        Action : "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudwatch_firehose_write_only" {
  name = "FirehosePutRecords"
  role = aws_iam_role.cloudwatch_firehose_write_only.id

  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Action : [
          "firehose:PutRecord",
          "firehose:PutRecordBatch"
        ]
        Resource : aws_kinesis_firehose_delivery_stream.cloudwatch_data_firehose.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cloudwatch_read_only" {
  role       = aws_iam_role.cloudwatch_firehose_write_only.id
  policy_arn = "arn:aws:iam::aws:policy/AmazonKinesisFirehoseReadOnlyAccess"
}

### Firehose
resource "aws_kinesis_firehose_delivery_stream" "cloudwatch_data_firehose" {
  name        = "cloudwatch-data-${var.aws_region}"
  destination = "extended_s3"

  extended_s3_configuration {
    bucket_arn         = aws_s3_bucket.cloudwatch_data_bucket.arn
    role_arn           = aws_iam_role.cloudwatch_data_firehose_role.arn
    prefix             = "cloudwatchlogs/"
    compression_format = "GZIP"

    # Data is flushed once one of the buffer hints are satisfied
    buffer_interval = 300
    buffer_size     = 128
  }
}

resource "aws_iam_role" "cloudwatch_data_firehose_role" {
  assume_role_policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Sid : "FirehoseServiceAssumeRole"
        Effect : "Allow",
        Principal : {
          Service : "firehose.amazonaws.com"
        },
        Action : "sts:AssumeRole",
        Condition : {
          StringEquals : { "sts:ExternalId" : var.aws_account_id }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "cloudwatch_firehose_managed_policy" {
  description = "Firehose permissions to write to data bucket"
  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Sid : "AllowS3Delivery"
        Effect : "Allow",
        Action : [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ],
        Resource : [
          aws_s3_bucket.cloudwatch_data_bucket.arn,
          "${aws_s3_bucket.cloudwatch_data_bucket.arn}/cloudwatch/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cloudwatch" {
  policy_arn = aws_iam_policy.cloudwatch_firehose_managed_policy.arn
  role       = aws_iam_role.cloudwatch_data_firehose_role.id
}

### S3 Bucket

resource "aws_s3_bucket" "cloudwatch_data_bucket" {
  acl = "private"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  # Short expiration because this data is sent to Panther.
  # This can be adjusted per your individual needs.
  lifecycle_rule {
    id      = "30DayExpiration"
    enabled = true
    expiration {
      days = 30
    }
    noncurrent_version_expiration {
      days = 30
    }
  }
}

resource aws_s3_bucket_policy "cloudwatch_data_bucket" {
  bucket     = aws_s3_bucket.cloudwatch_data_bucket.id
  depends_on = [aws_s3_bucket_public_access_block.cloudwatch_data_bucket]

  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Deny",
        Principal : "*",
        Action : "s3:GetObject",
        Resource : "${aws_s3_bucket.cloudwatch_data_bucket.arn}/*"
        Condition : {
          Bool : { "aws:SecureTransport" : false }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_public_access_block" "cloudwatch_data_bucket" {
  bucket                  = aws_s3_bucket.cloudwatch_data_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_notification" "cloudwatch_data_bucket" {
  bucket = aws_s3_bucket.cloudwatch_data_bucket.id

  topic {
    events = [
      "s3:ObjectCreated:*"
    ]
    topic_arn = var.s3_notifications_topic
  }
}