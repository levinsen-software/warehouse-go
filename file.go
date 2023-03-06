package warehouse

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

type File struct {
	ID           uuid.UUID `json:"file_id"`
	BundleID     uuid.UUID `json:"bundle_id"`
	ProjectID    uuid.UUID `json:"project_id"`
	CreatedTime  time.Time `json:"created_time"`
	ModifiedTime time.Time `json:"modified_time"`
	Downloads    int64     `json:"downloads"`
	Size         int64     `json:"size"`

	Props  map[string]interface{}
	client *Client
}

func newFile(c *Client) *File {
	return &File{
		client: c,
		Props:  make(map[string]interface{}),
	}
}

func (f *File) Get(key string) interface{} {
	return f.Props[key]
}

func (f *File) GetString(key string) string {
	if v, ok := f.Props[key].(string); ok {
		return v
	}
	return ""
}

func (f *File) GetObject(key string) map[string]interface{} {
	if m, ok := f.Props[key].(map[string]interface{}); ok {
		return m
	}
	return nil
}

func (f *File) GetInt(key string) int {
	if i, ok := f.Props[key].(int); ok {
		return i
	}
	return 0
}

func (f *File) Set(m map[string]interface{}) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/files/%s", f.client.address, f.ID.String()), bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("could not make request: %+v", err)
	}

	resp, err := f.client.do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("could not read body: %+v", err)
		}
		switch resp.StatusCode {
		case http.StatusNotFound:
			return fmt.Errorf("file does not exist")
		case http.StatusUnauthorized:
			return fmt.Errorf("login required")
		default:
			return fmt.Errorf("unknown HTTP status: %s, %s", resp.Status, b)
		}
	}

	io.Copy(io.Discard, resp.Body)
	return nil
}

func (f *File) Update(cmd []Update) error {
	b, err := json.Marshal(cmd)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%s/files/%s", f.client.address, f.ID.String()), bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("could not make request: %+v", err)
	}

	resp, err := f.client.do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("could not read body: %+v", err)
		}
		switch resp.StatusCode {
		case http.StatusNotFound:
			return fmt.Errorf("file does not exist")
		case http.StatusUnauthorized:
			return fmt.Errorf("login required")
		default:
			return fmt.Errorf("unknown HTTP status: %s, %s", resp.Status, b)
		}
	}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&f); err != nil {
		return err
	}

	return nil
}

func (f *File) Trash() error {
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/files/%s/trash", f.client.address, f.ID.String()), nil)
	if err != nil {
		return fmt.Errorf("could not make request: %+v", err)
	}

	resp, err := f.client.do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("could not read body: %+v", err)
		}
		switch resp.StatusCode {
		case http.StatusNotFound:
			return fmt.Errorf("file does not exist")
		case http.StatusUnauthorized:
			return fmt.Errorf("login required")
		default:
			return fmt.Errorf("unknown HTTP status: %s, %s", resp.Status, b)
		}
	}

	io.Copy(io.Discard, resp.Body)
	return nil
}

func (f *File) Restore() error {
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/files/%s/restore", f.client.address, f.ID.String()), nil)
	if err != nil {
		return fmt.Errorf("could not make request: %+v", err)
	}

	resp, err := f.client.do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("could not read body: %+v", err)
		}
		switch resp.StatusCode {
		case http.StatusNotFound:
			return fmt.Errorf("file does not exist")
		case http.StatusUnauthorized:
			return fmt.Errorf("login required")
		default:
			return fmt.Errorf("unknown HTTP status: %s, %s", resp.Status, b)
		}
	}

	io.Copy(io.Discard, resp.Body)
	return nil
}

type DownloadInfo struct {
	Body   io.ReadCloser
	Header http.Header
	Size   int64
	SHA512 []byte
}

func (f *File) Download() (*DownloadInfo, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/files/%s/download", f.client.address, f.ID.String()), nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.client.do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("could not read body: %+v", err)
		}
		switch resp.StatusCode {
		case http.StatusNotFound:
			return nil, fmt.Errorf("file does not exist")
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("login required")
		default:
			return nil, fmt.Errorf("unknown HTTP status: %s, %s", resp.Status, b)
		}
	}

	size, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("unable to parse size: %+v", err)
	}

	sha512, err := base64.StdEncoding.DecodeString(resp.Header.Get("X-Content-SHA512"))
	if err != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("unable to parse sha512: %+v", err)
	}

	d := &DownloadInfo{
		Body:   resp.Body,
		Header: resp.Header,
		Size:   size,
		SHA512: sha512,
	}

	return d, nil
}
