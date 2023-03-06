package warehouse

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type Bundle struct {
	ID           uuid.UUID
	ProjectID    uuid.UUID
	Files        []*File
	CreatedTime  time.Time
	ModifiedTime time.Time
	Props        map[string]interface{}
	client       *Client
}

func newBundle(c *Client) *Bundle {
	return &Bundle{
		client: c,
		Props:  make(map[string]interface{}),
	}
}

func (b *Bundle) Get(key string) interface{} {
	return b.Props[key]
}

func (b *Bundle) GetString(key string) string {
	if v, ok := b.Props[key].(string); ok {
		return v
	}
	return ""
}

func (b *Bundle) GetObject(key string) map[string]interface{} {
	if m, ok := b.Props[key].(map[string]interface{}); ok {
		return m
	}
	return nil
}

func (b *Bundle) GetInt(key string) int {
	if i, ok := b.Props[key].(int); ok {
		return i
	}
	return 0
}

func (b *Bundle) Set(m map[string]interface{}) error {
	Props, err := json.Marshal(m)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/bundles/%s", b.client.address, b.ID.String()), bytes.NewReader(Props))
	if err != nil {
		return fmt.Errorf("could not make request: %+v", err)
	}

	resp, err := b.client.do(req)
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
			return fmt.Errorf("bundle does not exist")
		case http.StatusUnauthorized:
			return fmt.Errorf("login required")
		default:
			return fmt.Errorf("unknown HTTP status: %s, %s", resp.Status, b)
		}
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

func (b *Bundle) Update(cmd []Update) error {
	props, err := json.Marshal(cmd)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%s/bundles/%s", b.client.address, b.ID.String()), bytes.NewReader(props))
	if err != nil {
		return fmt.Errorf("could not make request: %+v", err)
	}

	resp, err := b.client.do(req)
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
			return fmt.Errorf("bundle does not exist")
		case http.StatusUnauthorized:
			return fmt.Errorf("login required")
		default:
			return fmt.Errorf("unknown HTTP status: %s, %s", resp.Status, b)
		}
	}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&b); err != nil {
		return err
	}

	return nil
}

func (b *Bundle) Trash() error {
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/bundles/%s/trash", b.client.address, b.ID.String()), nil)
	if err != nil {
		return fmt.Errorf("could not make request: %+v", err)
	}

	resp, err := b.client.do(req)
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
			return fmt.Errorf("bundle does not exist")
		case http.StatusUnauthorized:
			return fmt.Errorf("login required")
		default:
			return fmt.Errorf("unknown HTTP status: %s, %s", resp.Status, b)
		}
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

func (b *Bundle) Restore() error {
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/bundles/%s/restore", b.client.address, b.ID.String()), nil)
	if err != nil {
		return fmt.Errorf("could not make request: %+v", err)
	}

	resp, err := b.client.do(req)
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
			return fmt.Errorf("bundle does not exist")
		case http.StatusUnauthorized:
			return fmt.Errorf("login required")
		default:
			return fmt.Errorf("unknown HTTP status: %s, %s", resp.Status, b)
		}
	}

	io.Copy(io.Discard, resp.Body)
	return nil
}

type hashingRequestReader struct {
	reader io.Reader
	req    *http.Request
	hash   hash.Hash
}

func newHashingRequestReader(r io.Reader) *hashingRequestReader {
	return &hashingRequestReader{
		reader: r,
		hash:   sha512.New(),
	}
}

func (h *hashingRequestReader) setRequest(req *http.Request) {
	h.req = req
	req.Header.Add("Trailer", "X-Content-Sha512")
	req.Trailer = make(http.Header)
	req.Trailer["X-Content-Sha512"] = nil
}

func (h *hashingRequestReader) Read(buf []byte) (int, error) {
	n, err := h.reader.Read(buf)
	if n > 0 {
		h.hash.Write(buf[:n])
	}
	if err == io.EOF {
		sha := h.hash.Sum(nil)
		h.req.Trailer.Set("X-Content-Sha512", base64.StdEncoding.EncodeToString(sha[:]))
	}
	return n, err
}

func (b *Bundle) Upload(r io.Reader, m map[string]string) (*File, error) {
	hr := newHashingRequestReader(r)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/bundles/%s/files", b.client.address, b.ID.String()), hr)
	if err != nil {
		return nil, fmt.Errorf("could not make request: %+v", err)
	}
	req.ContentLength = -1
	hr.setRequest(req)

	for k, v := range m {
		req.Header.Add("X-File-Property", fmt.Sprintf("%s=%s", k, v))
	}

	resp, err := b.client.do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("could not read body: %+v", err)
		}
		switch resp.StatusCode {
		case http.StatusNotFound:
			return nil, fmt.Errorf("bundle does not exist")
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("login required")
		default:
			return nil, fmt.Errorf("unknown HTTP status: %s, %s", resp.Status, b)
		}
	}

	i := newFile(b.client)
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&i); err != nil {
		return nil, err
	}
	return i, nil
}

func (b *Bundle) queryParam() Query {
	return NewEqualsQuery("bundle.id", b.ID.String())
}

func (b *Bundle) FindFiles(q Query, s Sorting, limit int) ([]*File, error) {
	q = NewAndQuery([]Query{b.queryParam(), q})
	return b.client.FindFiles(q, s, limit)
}

func (b *Bundle) FindFile(q Query, s Sorting, limit int) (*File, error) {
	q = NewAndQuery([]Query{b.queryParam(), q})
	return b.client.FindFile(q, s)
}

type ArchiveType int

const (
	ArchiveTypeInvalid ArchiveType = iota
	ArchiveTypeTar
	ArchiveTypeZip
)

func (b *Bundle) DownloadTar(t ArchiveType) (*DownloadInfo, error) {
	var url string
	switch t {
	case ArchiveTypeTar:
		url = fmt.Sprintf("%s/bundles/%s/downloadtar", b.client.address, b.ID.String())
	case ArchiveTypeZip:
		url = fmt.Sprintf("%s/bundles/%s/downloadzip", b.client.address, b.ID.String())
	default:
		return nil, fmt.Errorf("invalid archive type")
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := b.client.do(req)
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
			return nil, fmt.Errorf("bundle does not exist")
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("login required")
		default:
			return nil, fmt.Errorf("unknown HTTP status: %s, %s", resp.Status, b)
		}
	}

	d := &DownloadInfo{
		Body:   resp.Body,
		Header: resp.Header,
	}

	return d, nil
}
