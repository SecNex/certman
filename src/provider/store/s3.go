package store

import (
	"bytes"
	"io"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

type S3Provider struct {
	Url       string
	Bucket    string
	AccessKey string
	SecretKey string
	Client    *s3.S3
}

func NewS3(url string, bucket string, accessKey string, secretKey string) *S3Provider {
	s3Config := &aws.Config{
		Region:           aws.String("fsn1"),
		Endpoint:         aws.String(url),
		Credentials:      credentials.NewStaticCredentials(accessKey, secretKey, ""),
		S3ForcePathStyle: aws.Bool(true),
	}

	log.Printf("Initializing S3 client with URL: %s, Bucket: %s\n", url, bucket)
	s, err := session.NewSession(s3Config)
	if err != nil {
		panic(err)
	}

	log.Printf("S3 session initialized with URL: %s, Bucket: %s\n", url, bucket)

	s3Client := s3.New(s)
	log.Printf("S3 client initialized with URL: %s, Bucket: %s\n", url, bucket)
	log.Printf("S3 API Version: %s\n", s3Client.APIVersion)

	return &S3Provider{
		Url:       url,
		Bucket:    bucket,
		AccessKey: accessKey,
		SecretKey: secretKey,
		Client:    s3Client,
	}
}

func (s *S3Provider) Get(path string) ([]byte, error) {
	log.Printf("Downloading file from S3: %s\n", path)
	res, err := s.Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(path),
	})
	if err != nil {
		return nil, err
	}

	data := make([]byte, *res.ContentLength)
	_, err = res.Body.Read(data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (s *S3Provider) List(path string) ([]string, error) {
	log.Printf("Listing files in S3: %s\n", path)
	res, err := s.Client.ListObjectsV2(&s3.ListObjectsV2Input{
		Bucket: aws.String(s.Bucket),
		Prefix: aws.String(path),
	})
	if err != nil {
		return nil, err
	}

	var files []string

	for _, obj := range res.Contents {
		log.Printf("Name: %s, Größe: %d Bytes\n", *obj.Key, *obj.Size)
		files = append(files, *obj.Key)
	}

	return files, nil
}

func (s *S3Provider) New(path string, data []byte) error {
	log.Printf("Uploading file to S3: %s\n", path)
	reader := io.Reader(bytes.NewReader(data))
	_, err := s.Client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(path),
		Body:   aws.ReadSeekCloser(reader),
		// SSECustomerAlgorithm: aws.String("AES256"),
	})
	if err != nil {
		return err
	}

	return nil
}
