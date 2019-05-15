package escalate

import (
	"testing"

	"github.com/mayuresh82/auto_remediation/executor"
	"github.com/mayuresh82/auto_remediation/models"
	"github.com/stretchr/testify/assert"
	jira "gopkg.in/andygrunwald/go-jira.v1"
)

type mockJiraClient struct {
	comments []string
}

func (c *mockJiraClient) AddComment(taskID string, comment *jira.Comment) error {
	c.comments = append(c.comments, comment.Body)
	return nil
}

func (c *mockJiraClient) Create(i *jira.Issue) (*jira.Issue, error) {
	i.Key = "TASK-123"
	return i, nil
}

func (c *mockJiraClient) GetIssue(issueKey string) (*jira.Issue, error) {
	return &jira.Issue{
		Key: "TASK-444", Fields: &jira.IssueFields{Status: &jira.Status{Name: "Open"}},
	}, nil
}

func TestJiraEscalate(t *testing.T) {
	client := &mockJiraClient{}
	esc := &JiraEscalator{project: "PROJ-1", client: client}
	req := &EscalationRequest{
		Rem: &models.Remediation{}, Inc: executor.Incident{Id: 100, Name: "Dummy Incident"},
		Params: map[string]string{"description": "dummy failed"},
	}
	err := esc.Escalate(req)
	assert.Nil(t, err)
	assert.Equal(t, req.Rem.TaskId, "TASK-123")
	assert.Equal(t, len(client.comments), 0)

	req.Params["comment"] = "This comment"
	err = esc.Escalate(req)
	assert.Equal(t, client.comments[0], "This comment")
}

func TestLoadTasks(t *testing.T) {
	client := &mockJiraClient{}
	esc := &JiraEscalator{project: "PROJ-1", client: client}
	task := &Task{}
	assert.Error(t, esc.LoadTask(task))
	task.ID = "TASK-444"
	esc.LoadTask(task)
	assert.Equal(t, task.Status, TaskStatusOpen)
}
