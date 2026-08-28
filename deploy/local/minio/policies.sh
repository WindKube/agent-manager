#!/bin/sh
# Bucket bootstrap and the object-store half of the credential boundary.
#
# Two users, not one. The Go type system already hands the scanner a
# blob.Reader with no write method (internal/blob), but a type boundary is only
# as good as the credential behind it: with one root key, code that bypassed the
# interface would still succeed. am-fetcher can write; am-reader cannot, and the
# api, scanner and seed roles hold only that key.
set -eu

mc alias set local "http://minio:9000" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"
mc mb --ignore-existing "local/$BUCKET"

cat >/tmp/rw.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads"],
      "Resource": ["arn:aws:s3:::$BUCKET"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload",
                 "s3:ListMultipartUploadParts"],
      "Resource": ["arn:aws:s3:::$BUCKET/*"]
    }
  ]
}
JSON

cat >/tmp/ro.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::$BUCKET"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::$BUCKET/*"]
    }
  ]
}
JSON

mc admin policy create local agent-manager-rw /tmp/rw.json || true
mc admin policy create local agent-manager-ro /tmp/ro.json || true

mc admin user add local "$WRITER_KEY" "$WRITER_SECRET"
mc admin user add local "$READER_KEY" "$READER_SECRET"
mc admin policy attach local agent-manager-rw --user "$WRITER_KEY" || true
mc admin policy attach local agent-manager-ro --user "$READER_KEY" || true

echo "minio-init: bucket $BUCKET ready; writer=$WRITER_KEY reader=$READER_KEY"
