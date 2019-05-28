package escalate

import (
	"testing"

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
		Key: issueKey, Fields: &jira.IssueFields{
			Status:  &jira.Status{Name: "Open"},
			Summary: "foobar",
		},
	}, nil
}

func (c *mockJiraClient) UpdateIssue(issueKey string, data map[string]interface{}) error {
	return nil
}

func TestJiraCreate(t *testing.T) {
	client := &mockJiraClient{}
	esc := &JiraEscalator{project: "PROJ-1", client: client}
	task := &Task{Title: "foobar", Params: map[string]string{"description": "foobar task"}}
	err := esc.CreateTask(task)
	assert.Nil(t, err)
	assert.Equal(t, task.ID, "TASK-123")
	assert.Equal(t, len(client.comments), 0)

	task.Params["comment"] = "This comment"
	err = esc.UpdateTask(task)
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
	assert.Equal(t, task.Title, "foobar")
}
