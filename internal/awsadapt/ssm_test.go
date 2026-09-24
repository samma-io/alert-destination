package awsadapt_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/samma-io/alert-destination/internal/awsadapt"
)

type fakeSSM struct {
	calls   []*ssm.GetParametersInput
	params  map[string]string
	invalid []string
	err     error
}

func (f *fakeSSM) GetParameters(_ context.Context, in *ssm.GetParametersInput,
	_ ...func(*ssm.Options)) (*ssm.GetParametersOutput, error) {

	f.calls = append(f.calls, in)
	if f.err != nil {
		return nil, f.err
	}
	out := &ssm.GetParametersOutput{InvalidParameters: f.invalid}
	for _, n := range in.Names {
		if v, ok := f.params[n]; ok {
			out.Parameters = append(out.Parameters, ssmtypes.Parameter{
				Name: aws.String(n), Value: aws.String(v),
			})
		}
	}
	return out, nil
}

func TestParameterStore_ReadsEveryNameInOneCall(t *testing.T) {
	f := &fakeSSM{params: map[string]string{"/a/SLACK": "s", "/a/GITHUB": "g"}}
	store := &awsadapt.ParameterStore{API: f}

	got, err := store.Get(context.Background(), "/a/SLACK", "/a/GITHUB")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(f.calls) != 1 {
		t.Errorf("calls = %d, want 1; SSM throughput is account-wide", len(f.calls))
	}
	if got["/a/SLACK"] != "s" || got["/a/GITHUB"] != "g" {
		t.Errorf("Get = %v", got)
	}
}

// Without decryption a SecureString comes back as ciphertext, which presents
// downstream as a bad token rather than as a missing permission.
func TestParameterStore_DecryptsSecureStrings(t *testing.T) {
	f := &fakeSSM{params: map[string]string{"/a/SLACK": "s"}}
	store := &awsadapt.ParameterStore{API: f}

	if _, err := store.Get(context.Background(), "/a/SLACK"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if f.calls[0].WithDecryption == nil || !*f.calls[0].WithDecryption {
		t.Error("WithDecryption is not set")
	}
}

// A name SSM does not know is absent from Parameters and listed in
// InvalidParameters, with no error. Ignoring that returns an empty value and the
// caller reports a bad token instead of an unset one.
func TestParameterStore_OmitsInvalidParameters(t *testing.T) {
	f := &fakeSSM{params: map[string]string{}, invalid: []string{"/a/NOPE"}}
	store := &awsadapt.ParameterStore{API: f}

	got, err := store.Get(context.Background(), "/a/NOPE")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, present := got["/a/NOPE"]; present {
		t.Error("an invalid parameter was returned as though it had a value")
	}
}

// SSM caps GetParameters at ten names per call.
func TestParameterStore_BatchesBeyondTheAPILimit(t *testing.T) {
	params := map[string]string{}
	var names []string
	for i := 0; i < 23; i++ {
		n := string(rune('a'+i)) + "/p"
		names = append(names, n)
		params[n] = "v"
	}
	f := &fakeSSM{params: params}
	store := &awsadapt.ParameterStore{API: f}

	got, err := store.Get(context.Background(), names...)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got) != 23 {
		t.Errorf("got %d parameters, want 23", len(got))
	}
	for i, call := range f.calls {
		if len(call.Names) > awsadapt.MaxParametersPerCall {
			t.Errorf("call %d asked for %d names, over the API's limit of %d",
				i, len(call.Names), awsadapt.MaxParametersPerCall)
		}
	}
}

func TestParameterStore_PropagatesAnAPIError(t *testing.T) {
	store := &awsadapt.ParameterStore{API: &fakeSSM{err: errors.New("ThrottlingException")}}

	if _, err := store.Get(context.Background(), "/a/SLACK"); err == nil {
		t.Fatal("Get succeeded despite an SSM error")
	}
}

func TestParameterStore_NoNamesMakesNoCall(t *testing.T) {
	f := &fakeSSM{}
	store := &awsadapt.ParameterStore{API: f}

	if _, err := store.Get(context.Background()); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("calls = %d, want 0", len(f.calls))
	}
}
