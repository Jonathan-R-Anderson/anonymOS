package s3api

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/syndichan/maniwani/storage-client/internal/store"
)

func TestAWSGoSDKRoundTrip(t *testing.T) {
	storage, err := store.Open(t.TempDir(), 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	const accessKey = "SYNTESTACCESS"
	const secretKey = "test-secret-key-with-at-least-32-bytes"
	server := httptest.NewServer(New(storage, accessKey, secretKey, log.New(io.Discard, "", 0)))
	defer server.Close()

	client := awss3.New(awss3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(server.URL),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
	})
	ctx := context.Background()
	if _, err := client.CreateBucket(ctx, &awss3.CreateBucketInput{Bucket: aws.String("sdk-test")}); err != nil {
		t.Fatal(err)
	}
	policy := `{"Version":"2012-10-17","Statement":[]}`
	if _, err := client.PutBucketPolicy(ctx, &awss3.PutBucketPolicyInput{
		Bucket: aws.String("sdk-test"), Policy: aws.String(policy),
	}); err != nil {
		t.Fatal(err)
	}
	policyResult, err := client.GetBucketPolicy(ctx, &awss3.GetBucketPolicyInput{
		Bucket: aws.String("sdk-test"),
	})
	if err != nil || aws.ToString(policyResult.Policy) != policy {
		t.Fatalf("bucket policy round trip failed: %v %#v", err, policyResult)
	}
	body := bytes.Repeat([]byte("AWS SDK unchanged\n"), 1000)
	if _, err := client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String("sdk-test"), Key: aws.String("path/object.txt"),
		Body: bytes.NewReader(body), ContentType: aws.String("text/plain"),
	}); err != nil {
		t.Fatal(err)
	}
	result, err := client.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String("sdk-test"), Key: aws.String("path/object.txt"),
	})
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := io.ReadAll(result.Body)
	result.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, body) {
		t.Fatal("SDK round-trip body mismatch")
	}
	publicPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::sdk-test/*"}]}`
	if _, err := client.PutBucketPolicy(ctx, &awss3.PutBucketPolicyInput{
		Bucket: aws.String("sdk-test"), Policy: aws.String(publicPolicy),
	}); err != nil {
		t.Fatal(err)
	}
	publicResponse, err := http.Get(server.URL + "/sdk-test/path/object.txt")
	if err != nil {
		t.Fatal(err)
	}
	publicBody, readErr := io.ReadAll(publicResponse.Body)
	publicResponse.Body.Close()
	if readErr != nil || publicResponse.StatusCode != 200 || !bytes.Equal(publicBody, body) {
		t.Fatalf("public policy read failed: HTTP %d err=%v", publicResponse.StatusCode, readErr)
	}
	listed, err := client.ListObjectsV2(ctx, &awss3.ListObjectsV2Input{
		Bucket: aws.String("sdk-test"), Prefix: aws.String("path/"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Contents) != 1 || aws.ToString(listed.Contents[0].Key) != "path/object.txt" {
		t.Fatalf("unexpected listing: %#v", listed.Contents)
	}
	multipart, err := client.CreateMultipartUpload(ctx, &awss3.CreateMultipartUploadInput{
		Bucket: aws.String("sdk-test"), Key: aws.String("path/multipart.bin"),
		ContentType: aws.String("application/octet-stream"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var completedParts []types.CompletedPart
	var multipartBody []byte
	for number, value := range [][]byte{
		bytes.Repeat([]byte("first-part"), 1000),
		bytes.Repeat([]byte("second-part"), 1000),
	} {
		partNumber := int32(number + 1)
		part, err := client.UploadPart(ctx, &awss3.UploadPartInput{
			Bucket: aws.String("sdk-test"), Key: aws.String("path/multipart.bin"),
			UploadId: multipart.UploadId, PartNumber: aws.Int32(partNumber),
			Body: bytes.NewReader(value),
		})
		if err != nil {
			t.Fatal(err)
		}
		completedParts = append(completedParts, types.CompletedPart{
			ETag: part.ETag, PartNumber: aws.Int32(partNumber),
		})
		multipartBody = append(multipartBody, value...)
	}
	if _, err := client.CompleteMultipartUpload(ctx, &awss3.CompleteMultipartUploadInput{
		Bucket: aws.String("sdk-test"), Key: aws.String("path/multipart.bin"),
		UploadId:        multipart.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: completedParts},
	}); err != nil {
		t.Fatal(err)
	}
	multipartResult, err := client.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String("sdk-test"), Key: aws.String("path/multipart.bin"),
	})
	if err != nil {
		t.Fatal(err)
	}
	recoveredMultipart, err := io.ReadAll(multipartResult.Body)
	multipartResult.Body.Close()
	if err != nil || !bytes.Equal(recoveredMultipart, multipartBody) {
		t.Fatalf("multipart round trip failed: %v", err)
	}
	if _, err := client.DeleteObjects(ctx, &awss3.DeleteObjectsInput{
		Bucket: aws.String("sdk-test"),
		Delete: &types.Delete{Objects: []types.ObjectIdentifier{
			{Key: aws.String("path/object.txt")},
			{Key: aws.String("path/multipart.bin")},
		}},
	}); err != nil {
		t.Fatal(err)
	}
}
