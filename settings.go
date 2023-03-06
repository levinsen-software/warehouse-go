package warehouse

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func (c *Client) SettingsCategory(cat string, v interface{}) error {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/settings/%s", c.address, cat), nil)
	if err != nil {
		return err
	}

	resp, err := c.do(req)
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
			return fmt.Errorf("setting does not exist")
		case http.StatusUnauthorized:
			return fmt.Errorf("login required")
		default:
			return fmt.Errorf("unknown HTTP status: %s, %s", resp.Status, b)
		}
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(b, v); err != nil {
		return err
	}

	return nil
}

func (c *Client) ProjectSettingsCategory(proj, cat string, v interface{}) error {
	proj = url.PathEscape(proj)
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/projects/%s/settings/%s", c.address, proj, cat), nil)
	if err != nil {
		return err
	}

	resp, err := c.do(req)
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
			return fmt.Errorf("setting does not exist")
		case http.StatusUnauthorized:
			return fmt.Errorf("login required")
		default:
			return fmt.Errorf("unknown HTTP status: %s, %s", resp.Status, b)
		}
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(b, v); err != nil {
		return err
	}

	return nil
}
