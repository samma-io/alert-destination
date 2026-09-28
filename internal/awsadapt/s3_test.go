package awsadapt_test

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/samma-io/alert-destination/internal/awsadapt"
)

type fakeS3 struct {
	in   *s3.PutObjectInput
	body []byte
	err  error
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput,
	_ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {

	f.in = in
	f.body, _ = io.ReadAll(in.Body)
	if f.err != nil {
		return nil, f.err
	}
	return &s3.PutObjectOutput{}, nil
}

func TestObjectStore_PutsTheBodyUnderTheKey(t *testing.T) {
	f := &fakeS3{}
	store := &awsadapt.ObjectStore{API: f, Bucket: "detections-123456789012"}

	key := "alerts/log_source=aws/date=2026-09-02/det_1.json"
	if err := store.Put(context.Background(), key, []byte("{}\n")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if aws.ToString(f.in.Bucket) != "detections-123456789012" || aws.ToString(f.in.Key) != key {
		t.Errorf("put s3://%s/%s", aws.ToString(f.in.Bucket), aws.ToString(f.in.Key))
	}
	if string(f.body) != "{}\n" || aws.ToInt64(f.in.ContentLength) != 3 {
		t.Errorf("body = %q, length = %d", f.body, aws.ToInt64(f.in.ContentLength))
	}
}

func TestObjectStore_ReportsTheError(t *testing.T) {
	boom := errors.New("AccessDenied")
	store := &awsadapt.ObjectStore{API: &fakeS3{err: boom}, Bucket: "b"}

	if err := store.Put(context.Background(), "k", nil); !errors.Is(err, boom) {
		t.Errorf("Put = %v, want it to wrap the SDK error", err)
	}
}
