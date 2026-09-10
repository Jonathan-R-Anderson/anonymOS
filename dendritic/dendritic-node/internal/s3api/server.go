package s3api

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/store"
	"github.com/syndichan/maniwani/storage-client/internal/traffic"
)

type Server struct {
	store   *store.Store
	auth    Authenticator
	logger  *log.Logger
	maxBody int64
	mu      sync.RWMutex
	uploads map[string]*multipartUpload
	// recaller reaches the peers. nil on a gateway-only process, in which case
	// the recall route answers 503 rather than pretending nothing was placed.
	recaller Recaller
	// Meter counts bytes served to callers, for the network throughput figure
	// on the public status page. Optional and nil-safe: a node that is not
	// reporting simply has none, and the coordinator reads an absent report as
	// "not measuring" rather than as "measured zero".
	meter *traffic.Meter
}

// SetMeter attaches the traffic meter. Separate from New so the meter can be
// owned by the process and shared with the other things that serve bytes,
// rather than each subsystem keeping a count nobody adds up.
func (s *Server) SetMeter(m *traffic.Meter) { s.meter = m }

type multipartUpload struct {
	ID          string
	Bucket      string
	Key         string
	ContentType string
	Parts       map[int]multipartPart
	CreatedAt   time.Time
}

type multipartPart struct {
	Number int
	Key    string
	ETag   string
	Size   int64
}

func New(storage *store.Store, accessKey, secretKey string, logger *log.Logger) *Server {
	return &Server{
		store: storage, auth: Authenticator{AccessKey: accessKey, SecretKey: secretKey},
		logger: logger, maxBody: 5 << 30,
		uploads: make(map[string]*multipartUpload),
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d-%s", time.Now().UnixNano(), r.RemoteAddr))))[:16]
	w.Header().Set("x-amz-request-id", requestID)
	w.Header().Set("Server", "SyndichanStorageNode")
	bucket, key := splitPath(r.URL.Path)
	query := r.URL.Query()
	var auth AuthResult
	// The public-read bypass is for OBJECT BYTES only. It never inspected the
	// query string, so without the placementQuery() term the ledger surface --
	// which names every peer holding a shard, and can order those shards
	// destroyed -- would be readable and callable with no credential at all on
	// every public-read bucket (arcade, static, releases).
	if placementQuery(query) || !(bucket != "" && key != "" &&
		(r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		s.publicReadAllowed(bucket)) {
		var err error
		auth, err = s.auth.Verify(r)
		if err != nil {
			s3Error(w, "SignatureDoesNotMatch", err.Error(), http.StatusForbidden, requestID)
			return
		}
	}
	if strings.HasPrefix(key, ".syndichan-multipart/") {
		s3Error(w, "AccessDenied", "This object-key prefix is reserved.", http.StatusForbidden, requestID)
		return
	}
	switch {
	// The placement ledger, as query subresources -- the extension pattern this
	// gateway already uses for ?policy / ?delete / ?uploads. Listed first so no
	// object route can shadow them.
	case bucket == "" && query.Has("placement") && r.Method == http.MethodGet:
		s.ledgerSummary(w, requestID)
	case bucket != "" && key == "" && query.Has("placement") && r.Method == http.MethodGet:
		s.listPlacements(w, r, bucket, requestID)
	case bucket != "" && key != "" && query.Has("placement") && r.Method == http.MethodGet:
		s.objectPlacement(w, bucket, key, requestID)
	case bucket != "" && key != "" && query.Has("recall") && r.Method == http.MethodGet:
		s.recallStatus(w, bucket, key, requestID)
	case bucket != "" && key != "" && query.Has("recall") && r.Method == http.MethodPost:
		s.recallObject(w, r, bucket, key, requestID)
	case bucket != "" && key != "" && query.Has("uploads") && r.Method == http.MethodPost:
		s.createMultipartUpload(w, r, bucket, key, requestID)
	case bucket != "" && key != "" && query.Get("uploadId") != "" &&
		query.Get("partNumber") != "" && r.Method == http.MethodPut:
		s.uploadPart(w, r, bucket, key, query.Get("uploadId"), query.Get("partNumber"), auth.PayloadHash, requestID)
	case bucket != "" && key != "" && query.Get("uploadId") != "" && r.Method == http.MethodPost:
		s.completeMultipartUpload(w, r, bucket, key, query.Get("uploadId"), auth.PayloadHash, requestID)
	case bucket != "" && key != "" && query.Get("uploadId") != "" && r.Method == http.MethodDelete:
		s.abortMultipartUpload(w, bucket, key, query.Get("uploadId"), requestID)
	case bucket != "" && key == "" && query.Has("policy") && r.Method == http.MethodPut:
		s.putBucketPolicy(w, r, bucket, auth.PayloadHash, requestID)
	case bucket != "" && key == "" && query.Has("policy") && r.Method == http.MethodGet:
		s.getBucketPolicy(w, bucket, requestID)
	case bucket != "" && key == "" && query.Has("policy") && r.Method == http.MethodDelete:
		s.deleteBucketPolicy(w, bucket)
	case bucket != "" && key == "" && query.Has("delete") && r.Method == http.MethodPost:
		s.deleteObjects(w, r, bucket, auth.PayloadHash, requestID)
	case bucket == "" && r.Method == http.MethodGet:
		s.listBuckets(w, requestID)
	case bucket != "" && key == "" && r.Method == http.MethodPut:
		s.createBucket(w, bucket, requestID)
	case bucket != "" && key == "" && r.Method == http.MethodHead:
		s.headBucket(w, bucket, requestID)
	case bucket != "" && key == "" && r.Method == http.MethodDelete:
		s.deleteBucket(w, bucket, requestID)
	case bucket != "" && key == "" && r.Method == http.MethodGet:
		s.listObjects(w, bucket, r.URL.Query().Get("prefix"), requestID)
	case bucket != "" && key != "" && r.Method == http.MethodPut:
		s.putObject(w, r, bucket, key, auth.PayloadHash, requestID)
	case bucket != "" && key != "" && r.Method == http.MethodGet:
		s.getObject(w, bucket, key, false, requestID)
	case bucket != "" && key != "" && r.Method == http.MethodHead:
		s.getObject(w, bucket, key, true, requestID)
	case bucket != "" && key != "" && r.Method == http.MethodDelete:
		s.deleteObject(w, bucket, key)
	default:
		s3Error(w, "NotImplemented", "This S3 operation is not implemented.", http.StatusNotImplemented, requestID)
	}
}

func (s *Server) createMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key, requestID string) {
	if !s.store.BucketExists(bucket) {
		s3Error(w, "NoSuchBucket", "The specified bucket does not exist.", http.StatusNotFound, requestID)
		return
	}
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		s3Error(w, "InternalError", "Could not create multipart upload.", 500, requestID)
		return
	}
	id := base64.RawURLEncoding.EncodeToString(random)
	upload := &multipartUpload{
		ID: id, Bucket: bucket, Key: key, ContentType: r.Header.Get("Content-Type"),
		Parts: make(map[int]multipartPart), CreatedAt: time.Now().UTC(),
	}
	s.mu.Lock()
	s.uploads[id] = upload
	s.mu.Unlock()
	payload := struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		Xmlns    string   `xml:"xmlns,attr"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		UploadID string   `xml:"UploadId"`
	}{
		Xmlns:  "http://s3.amazonaws.com/doc/2006-03-01/",
		Bucket: bucket, Key: key, UploadID: id,
	}
	writeXML(w, http.StatusOK, payload)
}

func (s *Server) uploadPart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID, rawPartNumber, expectedHash, requestID string) {
	partNumber, err := strconv.Atoi(rawPartNumber)
	if err != nil || partNumber < 1 || partNumber > 10000 {
		s3Error(w, "InvalidArgument", "partNumber must be between 1 and 10000.", http.StatusBadRequest, requestID)
		return
	}
	s.mu.RLock()
	upload := s.uploads[uploadID]
	s.mu.RUnlock()
	if upload == nil || upload.Bucket != bucket || upload.Key != key {
		s3Error(w, "NoSuchUpload", "The specified multipart upload does not exist.", http.StatusNotFound, requestID)
		return
	}
	hiddenKey := ".syndichan-multipart/" + uploadID + "/" + strconv.Itoa(partNumber)
	reader := http.MaxBytesReader(w, r.Body, s.maxBody)
	var manifest *store.Manifest
	if expectedHash == "UNSIGNED-PAYLOAD" {
		manifest, err = s.store.PutTemporaryObject(bucket, hiddenKey, reader, "")
	} else {
		manifest, err = s.store.PutTemporaryObject(bucket, hiddenKey, reader, expectedHash)
	}
	if err != nil {
		code, status := "InternalError", http.StatusInternalServerError
		if errors.Is(err, store.ErrDigestMismatch) {
			code, status = "XAmzContentSHA256Mismatch", http.StatusBadRequest
		}
		s3Error(w, code, err.Error(), status, requestID)
		return
	}
	part := multipartPart{Number: partNumber, Key: hiddenKey, ETag: manifest.ObjectID, Size: manifest.PlainSize}
	s.mu.Lock()
	if current := s.uploads[uploadID]; current != nil {
		if previous, exists := current.Parts[partNumber]; exists && previous.Key != hiddenKey {
			_ = s.store.DeleteObject(bucket, previous.Key)
		}
		current.Parts[partNumber] = part
	}
	s.mu.Unlock()
	w.Header().Set("ETag", `"`+manifest.ObjectID+`"`)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) completeMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key, uploadID, expectedHash, requestID string) {
	body, ok := s.verifiedBody(w, r, expectedHash, 2<<20, requestID)
	if !ok {
		return
	}
	var requested struct {
		Parts []struct {
			PartNumber int    `xml:"PartNumber"`
			ETag       string `xml:"ETag"`
		} `xml:"Part"`
	}
	if err := xml.NewDecoder(bytes.NewReader(body)).Decode(&requested); err != nil || len(requested.Parts) == 0 {
		s3Error(w, "MalformedXML", "Complete multipart request is invalid.", http.StatusBadRequest, requestID)
		return
	}
	s.mu.RLock()
	upload := s.uploads[uploadID]
	s.mu.RUnlock()
	if upload == nil || upload.Bucket != bucket || upload.Key != key {
		s3Error(w, "NoSuchUpload", "The specified multipart upload does not exist.", http.StatusNotFound, requestID)
		return
	}
	parts := make([]multipartPart, 0, len(requested.Parts))
	lastPart := 0
	for _, requestedPart := range requested.Parts {
		part, exists := upload.Parts[requestedPart.PartNumber]
		if !exists || requestedPart.PartNumber <= lastPart ||
			strings.Trim(requestedPart.ETag, `"`) != part.ETag {
			s3Error(w, "InvalidPart", "A multipart part is missing, out of order, or has a different ETag.", http.StatusBadRequest, requestID)
			return
		}
		lastPart = requestedPart.PartNumber
		parts = append(parts, part)
	}
	reader, writer := io.Pipe()
	go func() {
		for _, part := range parts {
			if _, err := s.store.GetObject(bucket, part.Key, writer); err != nil {
				writer.CloseWithError(err)
				return
			}
		}
		writer.Close()
	}()
	manifest, err := s.store.PutObject(bucket, key, upload.ContentType, reader)
	reader.Close()
	if err != nil {
		s3Error(w, "InternalError", err.Error(), http.StatusInternalServerError, requestID)
		return
	}
	for _, part := range upload.Parts {
		_ = s.store.DeleteObject(bucket, part.Key)
	}
	s.mu.Lock()
	delete(s.uploads, uploadID)
	s.mu.Unlock()
	payload := struct {
		XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
		Xmlns    string   `xml:"xmlns,attr"`
		Location string   `xml:"Location"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		ETag     string   `xml:"ETag"`
	}{
		Xmlns:    "http://s3.amazonaws.com/doc/2006-03-01/",
		Location: "/" + bucket + "/" + key, Bucket: bucket, Key: key,
		ETag: `"` + manifest.ObjectID + `"`,
	}
	writeXML(w, http.StatusOK, payload)
}

func (s *Server) abortMultipartUpload(w http.ResponseWriter, bucket, key, uploadID, requestID string) {
	s.mu.Lock()
	upload := s.uploads[uploadID]
	if upload != nil && (upload.Bucket != bucket || upload.Key != key) {
		upload = nil
	}
	if upload != nil {
		delete(s.uploads, uploadID)
	}
	s.mu.Unlock()
	if upload == nil {
		s3Error(w, "NoSuchUpload", "The specified multipart upload does not exist.", http.StatusNotFound, requestID)
		return
	}
	for _, part := range upload.Parts {
		_ = s.store.DeleteObject(bucket, part.Key)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) publicReadAllowed(bucket string) bool {
	raw, err := s.store.BucketPolicy(bucket)
	if err != nil {
		return false
	}
	if len(raw) == 0 {
		return false
	}
	var policy struct {
		Statement []struct {
			Effect    string          `json:"Effect"`
			Principal json.RawMessage `json:"Principal"`
			Action    any             `json:"Action"`
			Resource  any             `json:"Resource"`
			Condition any             `json:"Condition"`
		} `json:"Statement"`
	}
	if json.Unmarshal(raw, &policy) != nil {
		return false
	}
	requiredResource := "arn:aws:s3:::" + bucket + "/*"
	for _, statement := range policy.Statement {
		if statement.Effect != "Allow" || statement.Condition != nil ||
			!publicPrincipal(statement.Principal) ||
			!stringOrListContains(statement.Action, "s3:GetObject") ||
			!stringOrListContains(statement.Resource, requiredResource) {
			continue
		}
		return true
	}
	return false
}

func publicPrincipal(raw json.RawMessage) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	if value == "*" {
		return true
	}
	if object, ok := value.(map[string]any); ok {
		return object["AWS"] == "*"
	}
	return false
}

func stringOrListContains(value any, expected string) bool {
	if value == expected {
		return true
	}
	if values, ok := value.([]any); ok {
		for _, item := range values {
			if item == expected {
				return true
			}
		}
	}
	return false
}

func (s *Server) verifiedBody(w http.ResponseWriter, r *http.Request, expectedHash string, limit int64, requestID string) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		s3Error(w, "InvalidRequest", "Could not read request body.", http.StatusBadRequest, requestID)
		return nil, false
	}
	if expectedHash != "UNSIGNED-PAYLOAD" {
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != strings.ToLower(expectedHash) {
			s3Error(w, "XAmzContentSHA256Mismatch", "The payload hash did not match.", http.StatusBadRequest, requestID)
			return nil, false
		}
	}
	return body, true
}

func (s *Server) putBucketPolicy(w http.ResponseWriter, r *http.Request, bucket, expectedHash, requestID string) {
	if !s.store.BucketExists(bucket) {
		s3Error(w, "NoSuchBucket", "The specified bucket does not exist.", http.StatusNotFound, requestID)
		return
	}
	body, ok := s.verifiedBody(w, r, expectedHash, 64<<10, requestID)
	if !ok {
		return
	}
	var parsed any
	if json.Unmarshal(body, &parsed) != nil {
		s3Error(w, "MalformedPolicy", "Bucket policy is not valid JSON.", http.StatusBadRequest, requestID)
		return
	}
	if err := s.store.SetBucketPolicy(bucket, body); err != nil {
		s3Error(w, "InternalError", "Could not persist bucket policy.", http.StatusInternalServerError, requestID)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getBucketPolicy(w http.ResponseWriter, bucket, requestID string) {
	policy, err := s.store.BucketPolicy(bucket)
	if err != nil {
		s3Error(w, "InternalError", "Could not read bucket policy.", http.StatusInternalServerError, requestID)
		return
	}
	if len(policy) == 0 {
		s3Error(w, "NoSuchBucketPolicy", "The bucket policy does not exist.", http.StatusNotFound, requestID)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(policy)
}

func (s *Server) deleteBucketPolicy(w http.ResponseWriter, bucket string) {
	_ = s.store.DeleteBucketPolicy(bucket)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteObjects(w http.ResponseWriter, r *http.Request, bucket, expectedHash, requestID string) {
	body, ok := s.verifiedBody(w, r, expectedHash, 2<<20, requestID)
	if !ok {
		return
	}
	var requestPayload struct {
		Objects []struct {
			Key string `xml:"Key"`
		} `xml:"Object"`
	}
	if err := xml.NewDecoder(bytes.NewReader(body)).Decode(&requestPayload); err != nil {
		s3Error(w, "MalformedXML", "Delete request is not valid XML.", http.StatusBadRequest, requestID)
		return
	}
	type deleted struct {
		Key string `xml:"Key"`
	}
	response := struct {
		XMLName xml.Name  `xml:"DeleteResult"`
		Xmlns   string    `xml:"xmlns,attr"`
		Deleted []deleted `xml:"Deleted"`
	}{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/"}
	for _, object := range requestPayload.Objects {
		if object.Key == "" {
			continue
		}
		_ = s.store.DeleteObject(bucket, object.Key)
		response.Deleted = append(response.Deleted, deleted{Key: object.Key})
	}
	writeXML(w, http.StatusOK, response)
}

func splitPath(path string) (string, string) {
	value := strings.TrimPrefix(path, "/")
	if value == "" {
		return "", ""
	}
	parts := strings.SplitN(value, "/", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

func (s *Server) listBuckets(w http.ResponseWriter, requestID string) {
	names, err := s.store.ListBuckets()
	if err != nil {
		s3Error(w, "InternalError", "Could not list buckets.", 500, requestID)
		return
	}
	type bucket struct {
		Name         string `xml:"Name"`
		CreationDate string `xml:"CreationDate"`
	}
	payload := struct {
		XMLName xml.Name `xml:"ListAllMyBucketsResult"`
		Xmlns   string   `xml:"xmlns,attr"`
		Owner   struct {
			ID          string `xml:"ID"`
			DisplayName string `xml:"DisplayName"`
		} `xml:"Owner"`
		Buckets []bucket `xml:"Buckets>Bucket"`
	}{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/"}
	payload.Owner.ID = "syndichan-local-node"
	payload.Owner.DisplayName = "Syndichan storage node"
	for _, name := range names {
		payload.Buckets = append(payload.Buckets, bucket{Name: name, CreationDate: time.Now().UTC().Format(time.RFC3339)})
	}
	writeXML(w, http.StatusOK, payload)
}

func (s *Server) createBucket(w http.ResponseWriter, bucket, requestID string) {
	if err := s.store.CreateBucket(bucket); err != nil {
		s3Error(w, "InvalidBucketName", err.Error(), http.StatusBadRequest, requestID)
		return
	}
	w.Header().Set("Location", "/"+bucket)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) headBucket(w http.ResponseWriter, bucket, requestID string) {
	if !s.store.BucketExists(bucket) {
		s3Error(w, "NoSuchBucket", "The specified bucket does not exist.", http.StatusNotFound, requestID)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) deleteBucket(w http.ResponseWriter, bucket, requestID string) {
	if err := s.store.DeleteBucket(bucket); err != nil {
		code := "BucketNotEmpty"
		status := http.StatusConflict
		if !s.store.BucketExists(bucket) {
			code, status = "NoSuchBucket", http.StatusNotFound
		}
		s3Error(w, code, err.Error(), status, requestID)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listObjects(w http.ResponseWriter, bucket, prefix, requestID string) {
	if !s.store.BucketExists(bucket) {
		s3Error(w, "NoSuchBucket", "The specified bucket does not exist.", http.StatusNotFound, requestID)
		return
	}
	objects, err := s.store.ListObjects(bucket, prefix)
	if err != nil {
		s3Error(w, "InternalError", "Could not list objects.", 500, requestID)
		return
	}
	type content struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int64  `xml:"Size"`
		StorageClass string `xml:"StorageClass"`
	}
	payload := struct {
		XMLName     xml.Name  `xml:"ListBucketResult"`
		Xmlns       string    `xml:"xmlns,attr"`
		Name        string    `xml:"Name"`
		Prefix      string    `xml:"Prefix"`
		KeyCount    int       `xml:"KeyCount"`
		MaxKeys     int       `xml:"MaxKeys"`
		IsTruncated bool      `xml:"IsTruncated"`
		Contents    []content `xml:"Contents"`
	}{
		Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/", Name: bucket,
		Prefix: prefix, KeyCount: len(objects), MaxKeys: 1000,
	}
	for _, object := range objects {
		if strings.HasPrefix(object.Key, ".syndichan-multipart/") {
			continue
		}
		payload.Contents = append(payload.Contents, content{
			Key: object.Key, LastModified: object.CreatedAt.Format(time.RFC3339),
			ETag: `"` + object.ObjectID + `"`, Size: object.PlainSize, StorageClass: "STANDARD",
		})
	}
	payload.KeyCount = len(payload.Contents)
	writeXML(w, http.StatusOK, payload)
}

func (s *Server) putObject(w http.ResponseWriter, r *http.Request, bucket, key, expectedHash, requestID string) {
	if r.ContentLength > s.maxBody {
		s3Error(w, "EntityTooLarge", "Object exceeds the configured limit.", http.StatusRequestEntityTooLarge, requestID)
		return
	}
	reader := http.MaxBytesReader(w, r.Body, s.maxBody)
	var manifest *store.Manifest
	var err error
	if expectedHash == "UNSIGNED-PAYLOAD" {
		manifest, err = s.store.PutObject(bucket, key, r.Header.Get("Content-Type"), reader)
	} else {
		manifest, err = s.store.PutObjectVerified(bucket, key, r.Header.Get("Content-Type"), reader, expectedHash)
	}
	if err != nil {
		code, status := "InternalError", http.StatusInternalServerError
		if errors.Is(err, os.ErrNotExist) {
			code, status = "NoSuchBucket", http.StatusNotFound
		} else if errors.Is(err, store.ErrDigestMismatch) {
			code, status = "XAmzContentSHA256Mismatch", http.StatusBadRequest
		}
		s3Error(w, code, err.Error(), status, requestID)
		return
	}
	w.Header().Set("ETag", `"`+manifest.ObjectID+`"`)
	w.Header().Set("x-amz-version-id", manifest.ObjectID)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) getObject(w http.ResponseWriter, bucket, key string, head bool, requestID string) {
	manifest, err := s.store.HeadObject(bucket, key)
	if err != nil {
		s3Error(w, "NoSuchKey", "The specified key does not exist.", http.StatusNotFound, requestID)
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(manifest.PlainSize, 10))
	w.Header().Set("Content-Type", manifest.ContentType)
	w.Header().Set("ETag", `"`+manifest.ObjectID+`"`)
	w.Header().Set("Last-Modified", manifest.CreatedAt.Format(http.TimeFormat))
	w.Header().Set("Accept-Ranges", "none")
	if head {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	// Counted through a wrapper rather than from the manifest's declared size.
	// A transfer that fails halfway moved the bytes it moved, and reporting the
	// intended size would credit this node for delivery it did not complete --
	// on a flaky link that difference is the whole story.
	counted := &countingWriter{w: w}
	_, err = s.store.GetObject(bucket, key, counted)
	s.meter.Serve(counted.n)
	if err != nil {
		s.logger.Printf("GET %s/%s failed after response began: %v", bucket, key, err)
	}
}

// countingWriter tallies bytes that actually reached the client.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	written, err := c.w.Write(p)
	c.n += int64(written)
	return written, err
}

func (s *Server) deleteObject(w http.ResponseWriter, bucket, key string) {
	_ = s.store.DeleteObject(bucket, key)
	w.WriteHeader(http.StatusNoContent)
}

type errorPayload struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestID string   `xml:"RequestId"`
}

func s3Error(w http.ResponseWriter, code, message string, status int, requestID string) {
	writeXML(w, status, errorPayload{Code: code, Message: message, RequestID: requestID})
}

func writeXML(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(value)
}
