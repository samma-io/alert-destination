package awsadapt

import (
	"bytes"
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/samma-io/alert-destination/internal/archive"
)

// S3API is the slice of S3 this package uses.
type S3API interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// ObjectStore implements archive.Store over one S3 bucket.
//
// It needs s3:PutObject on the archive prefix and nothing else: the key is a
// function of the alert, so a replay overwrites rather than checking first,
// which is what keeps s3:GetObject out of the function's policy. If the bucket
// uses SSE-KMS with a customer key, the role needs kms:GenerateDataKey on it.
type ObjectStore struct {
	API    S3API
	Bucket string
}

// Put writes one object.
func (o *ObjectStore) Put(ctx context.Context, key string, body []byte) error {
	_, err := o.API.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(o.Bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
		ContentType:   aws.String("application/x-ndjson"),
	})
	if err != nil {
		return fmt.Errorf("putting s3://%s/%s: %w", o.Bucket, key, err)
	}
	return nil
}

var _ archive.Store = (*ObjectStore)(nil)
