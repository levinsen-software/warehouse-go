package warehouse

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
)

var (
	ErrNoBundles = errors.New("no bundles found")
	ErrNoFiles   = errors.New("no files found")
)

type keyResult []interface{}
type searchResult struct {
	Results []keyResult `json:"results"`
	Count   int         `json:"count"`
}

func (s keyResult) GetAsString(i int) string {
	if v, ok := s[i].(string); ok {
		return v
	}
	if v, ok := s[i].(json.Number); ok {
		return v.String()
	}
	return ""
}

func (s keyResult) GetString(i int) string {
	if v, ok := s[i].(string); ok {
		return v
	}
	return ""
}

func (c *Client) FindBundles(q Query, s Sorting, limit int) ([]*Bundle, error) {
	keys := []string{"bundle.id"}

	keys = append(keys, s.Key)

	search, err := c.SearchKeys(KeySearch{
		Table:   "bundles",
		Query:   q,
		Sorting: s,
		Keys:    keys,
		Limit:   limit,
	})

	if err != nil {
		return nil, fmt.Errorf("could not find bundles: %v", err)
	}

	bundles := make([]*Bundle, len(search))
	for idx, res := range search {
		uuid := uuid.MustParse(res[0].(string))
		bundle, err := c.Bundle(uuid)

		if err != nil {
			return nil, fmt.Errorf("could not get bundle: %v", err)
		}

		bundles[idx] = bundle
	}

	return bundles, nil
}

func (c *Client) FindBundle(q Query, s Sorting) (*Bundle, error) {
	bundles, err := c.FindBundles(q, s, 1)
	if err != nil {
		return nil, fmt.Errorf("could not find bundles: %v", err)
	}

	if len(bundles) == 0 {
		return nil, ErrNoBundles
	}

	return bundles[0], nil
}

func (c *Client) FindFiles(q Query, s Sorting, limit int) ([]*File, error) {
	keys := []string{"file.id"}

	keys = append(keys, s.Key)

	search, err := c.SearchKeys(KeySearch{
		Table:   "files",
		Query:   q,
		Sorting: s,
		Keys:    keys,
		Limit:   limit,
	})

	if err != nil {
		return nil, fmt.Errorf("could not find files: %v", err)
	}

	files := make([]*File, len(search))
	for idx, res := range search {
		uuid := uuid.MustParse(res[0].(string))
		file, err := c.File(uuid)

		if err != nil {
			return nil, fmt.Errorf("could not get file: %v", err)
		}

		files[idx] = file
	}

	return files, nil
}

func (c *Client) FindFile(q Query, s Sorting) (*File, error) {
	files, err := c.FindFiles(q, s, 1)
	if err != nil {
		return nil, fmt.Errorf("could not find files: %v", err)
	}

	if len(files) == 0 {
		return nil, ErrNoFiles
	}

	return files[0], nil
}

func (c *Client) SearchKeys(s KeySearch) ([]keyResult, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/search/keys", c.address), bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("could not read body: %+v", err)
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("login required")
		}
		return nil, fmt.Errorf("unknown HTTP status: %s, %s", resp.Status, b)
	}

	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()

	var res searchResult
	if err := dec.Decode(&res); err != nil {
		return nil, err
	}

	return res.Results, nil
}
