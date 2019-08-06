package remediator

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	am "github.com/mayuresh82/auto_remediation/alert_manager"
	"github.com/mayuresh82/auto_remediation/escalate"
	"github.com/mayuresh82/auto_remediation/executor"
	"github.com/mayuresh82/auto_remediation/models"
	"github.com/stretchr/testify/assert"
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

type MockDb struct {
	getRemediations func() ([]*models.Remediation, error)
	*models.DB
}

func (d MockDb) Close() error {
	return nil
}

func (db *MockDb) NewRecord(i interface{}) (int64, error) {
	return 1, nil
}

func (db *MockDb) UpdateRecord(i interface{}) error {
	return nil
}

func (db *MockDb) GetRemediations(query string, args ...interface{}) ([]*models.Remediation, error) {
	if db.getRemediations != nil {
		return db.getRemediations()
	}
	return nil, fmt.Errorf("not found")
}

type MockClient struct{}

func (c *MockClient) Do(req *http.Request) (*http.Response, error) {
	body := []byte(`[{"status": "ACTIVE"}]`)
	if strings.HasSuffix(req.URL.String(), "10") {
		body = []byte(`[{"status": "CLEARED"}]`)
	}
	if strings.Contains(req.URL.String(), "agg_id") {
		body = []byte(`[{"alert": 40, "device": "d2", "entity": "e2"}, {"alert": 50, "device": "d3", "entity": "e3"}]`)
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

func (m *MockNotifier) Send(rem *models.Remediation, msg string) error {
	return nil
}

type MockEscalator struct {
}

func (m *MockEscalator) CreateTask(t *escalate.Task) error {
	t.ID = "TASK-99"
	return nil
}

func (m *MockEscalator) UpdateTask(task *escalate.Task) error {
	return nil
}

func (m *MockEscalator) LoadTask(t *escalate.Task) error {
	t.Status = escalate.TaskStatusOpen
	n := time.Now()
	if t.ID == "TASK1" {
		t.Created = n
	}
	if t.ID == "TASK2" {
		t.Created = n.Add(5 * time.Minute)
	}
	if t.ID == "TASK3" {
		t.Status = escalate.TaskStatusClosed
	}
	return nil
}

func TestIncidentProcessing(t *testing.T) {
	c := &ConfigHandler{
		Rules: []Rule{
			Rule{AlertName: "Test1", Attempts: 2, Enabled: true, Audits: cmds["audits_passed"], Remediations: cmds["remediations_passed"]},
			Rule{AlertName: "Test2", Enabled: false},
			Rule{AlertName: "Test3", Attempts: 2, Enabled: true, Audits: cmds["audits_failed"], Remediations: cmds["remediations_passed"]},
			Rule{AlertName: "Test4", Attempts: 2, Enabled: true, Audits: cmds["audits_passed"], Remediations: cmds["remediations_failed"]},
			Rule{AlertName: "Test5", Attempts: 3, Enabled: true, Audits: cmds["audits_passed"], Remediations: cmds["remediations_passed"]},
		},
	}
	db := &MockDb{}
	r := &Remediator{
		Config:   c,
		Db:       db,
		queue:    &MockQueue{},
		executor: &MockExecutor{},
		esc:      &MockEscalator{},
		notif:    &MockNotifier{},
		am:       &am.AlertManager{Client: &MockClient{}},
		exe:      make(map[int64]chan struct{}),
	}
	inc := executor.Incident{
		Name: "TestIncident 1",
		Id:   10,
		Type: "ACTIVE",
		Data: map[string]interface{}{
			"description": "dummy",
			"entity":      "e1",
			"device":      "d1",
		},
	}
	// system disabled
	assert.Nil(t, r.processIncident(inc))

	r.enabled = true
	// test no rules
	inc.Name = "Test6"
	rem := r.processIncident(inc)
	assert.Nil(t, rem)
	// test inactive rule
	inc.Name = "Test2"
	rem = r.processIncident(inc)
	assert.Nil(t, rem)

	// test inactive alert
	db.getRemediations = func() ([]*models.Remediation, error) { return []*models.Remediation{}, nil }
	inc.Name = "Test1"
	inc.Id = 10
	assert.Nil(t, r.processIncident(inc))

	// test existing remediation
	db.getRemediations = func() ([]*models.Remediation, error) {
		return []*models.Remediation{&models.Remediation{Id: 100, Attempts: 2, Status: models.Status_REMEDIATION_FAILED}}, nil
	}
	inc.Name = "Test5"
	inc.Id = 44
	rem = r.processIncident(inc)
	assert.Equal(t, rem.Id, int64(100))
	assert.Equal(t, rem.Status, models.Status_REMEDIATION_SUCCESS)

	db.getRemediations = func() ([]*models.Remediation, error) {
		return []*models.Remediation{
			&models.Remediation{Id: 100, Attempts: 2, TaskId: "TASK1"},
			&models.Remediation{Id: 200, Attempts: 2, TaskId: "TASK2", Status: models.Status_REMEDIATION_FAILED},
			&models.Remediation{Id: 300, Attempts: 2, TaskId: "TASK3"},
		}, nil
	}
	rem = r.processIncident(inc)
	assert.Equal(t, rem.Id, int64(200))
	assert.Equal(t, rem.Status, models.Status_REMEDIATION_SUCCESS)

	db.getRemediations = func() ([]*models.Remediation, error) {
		return []*models.Remediation{&models.Remediation{Id: 200, Attempts: 3, Status: models.Status_AUDIT_FAILED}}, nil
	}
	inc.Id = 55
	rem = r.processIncident(inc)
	assert.Equal(t, rem.Id, int64(200))
	assert.Equal(t, rem.Status, models.Status_AUDIT_FAILED)

	db.getRemediations = func() ([]*models.Remediation, error) { return []*models.Remediation{}, nil }
	// test failed audit
	inc.Name = "Test3"
	inc.Id = 20
	rem = r.processIncident(inc)
	assert.Equal(t, rem.Id, int64(1))
	assert.Equal(t, rem.Status, models.Status_AUDIT_FAILED)

	// test failed remediation
	inc.Name = "Test4"
	rem = r.processIncident(inc)
	assert.Equal(t, rem.Id, int64(1))
	assert.Equal(t, rem.Status, models.Status_REMEDIATION_FAILED)

	// test success
	inc.Name = "Test1"
	rem = r.processIncident(inc)
	assert.Equal(t, rem.Id, int64(1))
	assert.ElementsMatch(t, rem.Entities, []string{"d1:e1"})
	assert.Equal(t, rem.Status, models.Status_REMEDIATION_SUCCESS)

	// test aggregate incident
	inc.IsAggregate = true
	inc.Id = 30
	rem = r.processIncident(inc)
	assert.Equal(t, rem.Id, int64(1))
	assert.ElementsMatch(t, rem.Entities, []string{"d2:e2", "d3:e3"})
	assert.Contains(t, inc.Data, "components")
	components := inc.Data["components"].([]map[string]interface{})
	assert.Equal(t, len(components), 2)
	assert.Equal(t, components[0]["alert"].(float64), float64(40))
}

func TestIncidentEscalate(t *testing.T) {
	c := &ConfigHandler{
		Rules: []Rule{
			Rule{AlertName: "Test4", Enabled: true, Audits: cmds["audits_passed"], Remediations: cmds["remediations_failed"]},
			Rule{AlertName: "Test3", Enabled: true, DontEscalate: true, Audits: cmds["audits_passed"], Remediations: cmds["remediations_passed"]},
		},
	}
	mockEsc := &MockEscalator{}
	r := &Remediator{
		Config:   c,
		Db:       &MockDb{},
		queue:    &MockQueue{},
		executor: &MockExecutor{},
		notif:    &MockNotifier{},
		esc:      mockEsc,
		am:       &am.AlertManager{Client: &MockClient{}},
		exe:      make(map[int64]chan struct{}),
		enabled:  true,
	}
	inc := executor.Incident{
		Name: "Test4",
		Id:   20,
		Type: "ACTIVE",
		Data: map[string]interface{}{
			"description": "dummy",
			"entity":      "e1",
			"device":      "d1",
		},
	}
	rem := r.processIncident(inc)
	assert.Equal(t, rem.Status, models.Status_REMEDIATION_FAILED)
	assert.Equal(t, rem.TaskId, "TASK-99")

	inc.Name = "Test3"
	rem = r.processIncident(inc)
	assert.Equal(t, rem.Status, models.Status_REMEDIATION_SUCCESS)
	assert.Equal(t, rem.TaskId, "")
}
