package warehouse

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
)

type Project struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	Name           string

	c *Client
}

type Organization struct {
	ID       uuid.UUID
	Name     string
	projects []*Project

	c *Client
}

func (o *Organization) Projects() ([]*Project, error) {
	if o.projects != nil {
		return o.projects, nil
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/organizations/%s", o.c.address, o.ID.String()), nil)
	if err != nil {
		return nil, err
	}

	resp, err := o.c.do(req)
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
		Projects []struct {
			ProjectName string `json:"project_name"`
			ProjectID   string `json:"project_id"`
		} `json:"projects"`
	}

	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}

	var projects []*Project
	for _, p := range res.Projects {
		id, err := uuid.Parse(p.ProjectID)
		if err != nil {
			return nil, err
		}
		projects = append(projects, &Project{
			c:              o.c,
			ID:             id,
			Name:           p.ProjectName,
			OrganizationID: o.ID,
		})
	}

	return projects, nil
}

func (p *Project) queryParam() Query {
	return NewEqualsQuery("project.id", p.ID.String())
}

func (p *Project) FindBundles(q Query, s Sorting, limit int) ([]*Bundle, error) {
	q = NewAndQuery([]Query{p.queryParam(), q})
	return p.c.FindBundles(q, s, limit)
}

func (p *Project) FindBundle(q Query, s Sorting, limit int) (*Bundle, error) {
	q = NewAndQuery([]Query{p.queryParam(), q})
	return p.c.FindBundle(q, s)
}

func (p *Project) FindFiles(q Query, s Sorting, limit int) ([]*File, error) {
	q = NewAndQuery([]Query{p.queryParam(), q})
	return p.c.FindFiles(q, s, limit)
}

func (p *Project) FindFile(q Query, s Sorting, limit int) (*File, error) {
	q = NewAndQuery([]Query{p.queryParam(), q})
	return p.c.FindFile(q, s)
}

func (o *Organization) queryParam() Query {
	return NewEqualsQuery("organization.id", o.ID.String())
}

func (o *Organization) FindBundles(q Query, s Sorting, limit int) ([]*Bundle, error) {
	q = NewAndQuery([]Query{o.queryParam(), q})
	return o.c.FindBundles(q, s, limit)
}

func (o *Organization) FindBundle(q Query, s Sorting, limit int) (*Bundle, error) {
	q = NewAndQuery([]Query{o.queryParam(), q})
	return o.c.FindBundle(q, s)
}

func (o *Organization) FindFiles(q Query, s Sorting, limit int) ([]*File, error) {
	q = NewAndQuery([]Query{o.queryParam(), q})
	return o.c.FindFiles(q, s, limit)
}

func (o *Organization) FindFile(q Query, s Sorting, limit int) (*File, error) {
	q = NewAndQuery([]Query{o.queryParam(), q})
	return o.c.FindFile(q, s)
}
