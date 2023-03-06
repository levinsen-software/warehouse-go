package warehouse

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type UpdateAssign struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

type UpdateDelete struct {
	Key string `json:"key"`
}

type Update struct {
	Assign UpdateAssign `json:"assign"`
	Delete UpdateDelete `json:"delete"`
}

type Client struct {
	address                                    string
	rawAuth, apikey, token, username, password string
	client                                     *http.Client
	tlsconfig                                  *tls.Config
}

func (c *Client) DisableTLSVerification() {
	c.tlsconfig.InsecureSkipVerify = true
}

func (c *Client) SetCredentials(username, password string) {
	c.username = username
	c.password = password
	c.token = ""
	c.apikey = ""
	c.rawAuth = ""
}

func (c *Client) SetAPIKey(apikey string) {
	c.apikey = apikey
	c.rawAuth = ""
	c.token = ""
	c.username = ""
	c.password = ""
}

func (c *Client) SetToken(token string) {
	c.token = token
	c.rawAuth = ""
	c.apikey = ""
	c.username = ""
	c.password = ""
}

func (c *Client) SetRawAuth(auth string) {
	c.rawAuth = auth
	c.token = ""
	c.apikey = ""
	c.username = ""
	c.password = ""
}

func New(address string) *Client {
	tlsconf := &tls.Config{}

	t := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsconf,
	}

	return &Client{
		address: address,
		client: &http.Client{
			Transport: t,
		},
		tlsconfig: tlsconf,
	}
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	if err := c.setAuth(req); err != nil {
		return nil, err
	}

	return c.client.Do(req)
}

func (c *Client) setAuth(req *http.Request) error {
	if c.rawAuth != "" {
		req.Header.Set("Authorization", c.rawAuth)
	} else if c.token != "" {
		req.Header.Set("Authorization", "token "+c.token)
	} else if c.apikey != "" {
		req.Header.Set("Authorization", "apikey "+c.apikey)
	} else if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	return nil
}

func (c *Client) Login(username, password string) error {
	b, err := json.Marshal(struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		Tag         string `json:"tag"`
		Interactive bool   `json:"interactive"`
		Permanent   bool   `json:"permanent"`
		Validity    int    `json:"validity"`
	}{
		Username:    username,
		Password:    password,
		Interactive: true,
	})

	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/authenticate", c.address), bytes.NewReader(b))
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
		return fmt.Errorf("unknown HTTP status: %s, %s", resp.Status, b)
	}

	b, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var res struct {
		Token       string   `json:"token"`
		Interactive bool     `json:"interactive"`
		Admin       bool     `json:"admin"`
		DisplayName string   `json:"displayName"`
		Username    string   `json:"username"`
		Groups      []string `json:"groups"`
	}

	if err := json.Unmarshal(b, &res); err != nil {
		return err
	}

	c.SetToken(res.Token)
	return nil
}

func (c *Client) Bundle(id uuid.UUID) (*Bundle, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/bundles/%s", c.address, id.String()), nil)
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
		switch resp.StatusCode {
		case http.StatusNotFound:
			return nil, fmt.Errorf("bundle does not exist")
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("login required")
		default:
			return nil, fmt.Errorf("unknown HTTP status: %s, %s", resp.Status, b)
		}
	}

	g := newBundle(c)
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&g); err != nil {
		return nil, err
	}
	return g, nil
}

func (c *Client) File(id uuid.UUID) (*File, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/files/%s", c.address, id.String()), nil)
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
		switch resp.StatusCode {
		case http.StatusNotFound:
			return nil, fmt.Errorf("file does not exist")
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("login required")
		default:
			return nil, fmt.Errorf("unknown HTTP status: %s, %s", resp.Status, b)
		}
	}

	i := newFile(c)
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&i); err != nil {
		return nil, err
	}
	return i, nil
}

func (c *Client) FileNoProps(id uuid.UUID) (*File, error) {
	i := newFile(c)
	i.ID = id
	return i, nil
}

func (c *Client) Organizations() ([]*Organization, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/organizations", c.address), nil)
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

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var res struct {
		Organizations []struct {
			OrganizationName string `json:"organization_name"`
			OrganizationID   string `json:"organization_id"`
		} `json:"organizations"`
	}

	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}

	var organizations []*Organization
	for _, o := range res.Organizations {
		id, err := uuid.Parse(o.OrganizationID)
		if err != nil {
			return nil, err
		}
		organizations = append(organizations, &Organization{
			c:    c,
			ID:   id,
			Name: o.OrganizationName,
		})
	}

	return organizations, nil
}

func (c *Client) Organization(name string) (*Organization, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/organizations/%s", c.address, name), nil)
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

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var res struct {
		OrganizationName string `json:"organization_name"`
		OrganizationID   string `json:"organization_id"`
		Projects         []struct {
			ProjectName string `json:"project_name"`
			ProjectID   string `json:"project_id"`
		} `json:"projects"`
	}

	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}

	id, err := uuid.Parse(res.OrganizationID)
	if err != nil {
		return nil, err
	}
	var projects []*Project
	for _, p := range res.Projects {
		pid, err := uuid.Parse(p.ProjectID)
		if err != nil {
			return nil, err
		}
		projects = append(projects, &Project{
			c:              c,
			ID:             pid,
			Name:           p.ProjectName,
			OrganizationID: id,
		})
	}
	return &Organization{
		c:        c,
		ID:       id,
		Name:     res.OrganizationName,
		projects: projects,
	}, nil
}

func (c *Client) Project(name string) (*Project, error) {
	name = strings.Replace(name, "/", "%2F", 1)

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/projects/%s", c.address, name), nil)
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

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var res struct {
		ProjectName      string `json:"project_name"`
		ProjectID        string `json:"project_id"`
		OrganizationName string `json:"organization_name"`
		OrganizationID   string `json:"organization_id"`
	}

	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}

	pid, err := uuid.Parse(res.ProjectID)
	if err != nil {
		return nil, err
	}

	oid, err := uuid.Parse(res.OrganizationID)
	if err != nil {
		return nil, err
	}
	return &Project{
		c:              c,
		ID:             pid,
		Name:           res.ProjectName,
		OrganizationID: oid,
	}, nil
}
