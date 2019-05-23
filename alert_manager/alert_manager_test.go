package alert_manager

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockClient struct {
	do func() (*http.Response, error)
}

func (c *MockClient) Do(req *http.Request) (*http.Response, error) {
	if c.do != nil {
		return c.do()
	}
	return nil, fmt.Errorf("Invalid request")
}

func TestAlerManagerGet(t *testing.T) {
	c := &MockClient{}
	c.do = func() (*http.Response, error) {
		body := []byte(`[{"name": "Test1", "id": 100, "status": "ACTIVE"}]`)
		return &http.Response{StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewBuffer(body))}, nil
	}
	am := &AlertManager{Client: c}
	alerts, err := am.GetAlerts("http://am/blah")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, alerts[0]["name"].(string), "Test1")
	assert.Equal(t, alerts[0]["id"].(float64), float64(100))

	status, _ := am.GetStatus(100)
	assert.Equal(t, status, "ACTIVE")
}

func TestAlertManagerToken(t *testing.T) {
	c := &MockClient{}
	c.do = func() (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized}, nil
	}
	am := &AlertManager{Client: c}
	err := am.getToken("foo", "bar")
	assert.NotNil(t, err)
	c.do = func() (*http.Response, error) {
		body := []byte(`{"token": "abcdefg", "expires_at": 123456}`)
		return &http.Response{StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewBuffer(body))}, nil
	}
	err = am.getToken("foo", "bar")
	assert.Nil(t, err)
	assert.Equal(t, am.token, "abcdefg")
}
