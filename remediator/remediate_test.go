package remediator

import (
	"bytes"
	"context"
	"github.com/mayuresh82/auto_remediation/executor"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

type MockQueue struct {
	recv chan executor.Incident
}

func (q *MockQueue) Register(recv chan executor.Incident) {
	q.recv = recv
}

func (q *MockQueue) Shutdown() error {
	return nil
}

type MockExecutor struct{}

func (e *MockExecutor) Execute(ctx context.Context, cmds []executor.Command, maxParallel int) map[*executor.Command]*executor.CmdResult {
	ret := make(map[*executor.Command]*executor.CmdResult)
	for _, cmd := range cmds {
		switch cmd.Name {
		case "audit1":
			ret[&cmd] = &executor.CmdResult{RetCode: 0, Error: nil}
		case "audit2":
			ret[&cmd] = &executor.CmdResult{RetCode: 1, Error: nil}
		case "rem1":
			ret[&cmd] = &executor.CmdResult{RetCode: 0, Error: nil}
		case "rem2":
			ret[&cmd] = &executor.CmdResult{RetCode: 1, Error: nil}
		}
	}
	return ret
}

type MockDb struct{}

func (d MockDb) Close() error {
	return nil
}

func (db *MockDb) NewRecord(i interface{}) (int64, error) {
	return 1, nil
}

func (db *MockDb) UpdateRecord(i interface{}) error {
	return nil
}

func (db *MockDb) GetRemediation(query string, args ...interface{}) (*Remediation, error) {
	return &Remediation{}, nil
}

type MockClient struct{}

func (c *MockClient) Do(req *http.Request) (*http.Response, error) {
	body := []byte(`[{"status": "ACTIVE"}]`)
	if strings.HasSuffix(req.URL.String(), "10") {
		body = []byte(`[{"status": "CLEARED"}]`)
	}
	if strings.Contains(req.URL.String(), "agg_id") {
		body = []byte(`[{"alert": 40}, {"alert": 50}]`)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewBuffer(body))}, nil
}

var cmds = map[string][]executor.Command{
	"audits_pass": []executor.Command{
		executor.Command{Name: "audit1", Command: "cmd1", Args: []string{"arg1", "arg2"}},
	},
	"audits_failed": []executor.Command{
		executor.Command{Name: "audit2", Command: "cmd2", Args: []string{"arg1", "arg2"}},
	},
	"remediations_pass": []executor.Command{
		executor.Command{Name: "rem1", Command: "cmd1", Args: []string{"arg1", "arg2"}},
	},
	"remediations_failed": []executor.Command{
		executor.Command{Name: "rem2", Command: "cmd2", Args: []string{"arg1", "arg2"}},
	},
	"onclear": []executor.Command{
		executor.Command{Name: "onclear1", Command: "cmd3", Args: []string{"arg1", "arg2"}},
	},
}

type MockNotifier struct{}

func (m *MockNotifier) Send(rem *Remediation, msg string) error {
	return nil
}

func TestIncidentProcessing(t *testing.T) {
	c := &ConfigHandler{
		Rules: []Rule{
			Rule{AlertName: "Test1", Enabled: true, Audits: cmds["audits_passed"], Remediations: cmds["remediations_passed"]},
			Rule{AlertName: "Test2", Enabled: false},
			Rule{AlertName: "Test3", Enabled: true, Audits: cmds["audits_failed"], Remediations: cmds["remediations_passed"]},
			Rule{AlertName: "Test4", Enabled: true, Audits: cmds["audits_passed"], Remediations: cmds["remediations_failed"]},
		},
	}
	r := &Remediator{
		config:   c,
		queue:    &MockQueue{},
		executor: &MockExecutor{},
		db:       &MockDb{},
		notif:    &MockNotifier{},
		am:       &AlertManager{client: &MockClient{}},
		exe:      make(map[int64]chan struct{}),
	}
	inc := executor.Incident{
		Name: "TestIncident 1",
		Id:   10,
		Type: "ACTIVE",
		Data: map[string]interface{}{
			"description": "dummy",
			"entities":    []interface{}{"d1:e1"},
		},
	}
	// test no rules
	inc.Name = "Test5"
	rem := r.processIncident(inc)
	assert.Nil(t, rem)
	// rest inactive rule
	inc.Name = "Test2"
	rem = r.processIncident(inc)
	assert.Nil(t, rem)

	// test inactive alert
	inc.Name = "Test1"
	inc.Id = 10
	assert.Nil(t, r.processIncident(inc))

	// test failed audit
	inc.Name = "Test3"
	inc.Id = 20
	rem = r.processIncident(inc)
	assert.Equal(t, rem.Status, Status_AUDIT_FAILED)

	// test failed remediation
	inc.Name = "Test4"
	rem = r.processIncident(inc)
	assert.Equal(t, rem.Status, Status_REMEDIATION_FAILED)

	// test success
	inc.Name = "Test1"
	rem = r.processIncident(inc)
	assert.Equal(t, rem.Status, Status_REMEDIATION_SUCCESS)

	// test aggregate incident
	inc.IsAggregate = true
	inc.Id = 30
	rem = r.processIncident(inc)
	assert.Contains(t, inc.Data, "components")
	components := inc.Data["components"].([]map[string]interface{})
	assert.Equal(t, len(components), 2)
	assert.Equal(t, components[0]["alert"].(float64), float64(40))
}
