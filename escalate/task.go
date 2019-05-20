package escalate

import (
	"fmt"
	"sort"
	"time"

	"github.com/mayuresh82/auto_remediation/executor"
	"github.com/mayuresh82/auto_remediation/models"
	jira "gopkg.in/andygrunwald/go-jira.v1"
)

const label = "auto-remediated"

type TaskStatus int

const (
	TaskStatusOpen   TaskStatus = 1
	TaskStatusClosed TaskStatus = 2
	TaskStatusOther  TaskStatus = 3
)

type Task struct {
	ID, Description string
	Status          TaskStatus
	Created         time.Time
}

type Tasks []*Task

func (t Tasks) Latest() *Task {
	if len(t) == 0 {
		return nil
	}
	sort.Slice(t, func(i, j int) bool {
		return t[i].Created.After(t[j].Created)
	})
	return t[0]
}

type EscalationRequest struct {
	Rem    *models.Remediation
	Inc    executor.Incident
	Params map[string]string
}

type Escalator interface {
	// Escalate escalates by performing some action on a task
	Escalate(req *EscalationRequest) error
	// LoadTask fills in relevant task details
	LoadTask(task *Task) error
}

type jiraClienter interface {
	AddComment(string, *jira.Comment) error
	Create(*jira.Issue) (*jira.Issue, error)
	GetIssue(string) (*jira.Issue, error)
}

type jiraClient struct {
	*jira.Client
}

func (c *jiraClient) AddComment(taskID string, comment *jira.Comment) error {
	_, _, err := c.Client.Issue.AddComment(taskID, comment)
	return err
}

func (c *jiraClient) Create(i *jira.Issue) (*jira.Issue, error) {
	issue, _, err := c.Client.Issue.Create(i)
	if err != nil {
		return nil, err
	}
	return issue, nil
}

func (c *jiraClient) GetIssue(issueKey string) (*jira.Issue, error) {
	issue, _, err := c.Client.Issue.Get(issueKey, nil)
	return issue, err
}

var openJiraStates = []string{"Open", "To Do"}
var closedJiraStates = []string{"Closed", "Done"}

func in(elem string, list []string) bool {
	for _, e := range list {
		if e == elem {
			return true
		}
	}
	return false
}

type JiraEscalator struct {
	project string
	client  jiraClienter
}

func NewJiraEscalator(url, user, pass, project string) (*JiraEscalator, error) {
	tp := jira.BasicAuthTransport{
		Username: user,
		Password: pass,
	}
	jc, err := jira.NewClient(tp.Client(), url)
	if err != nil {
		return nil, err
	}
	return &JiraEscalator{
		project: project,
		client:  &jiraClient{jc},
	}, nil
}

func (j *JiraEscalator) Escalate(req *EscalationRequest) error {
	if req.Rem.TaskId != "" {
		return j.client.AddComment(req.Rem.TaskId, &jira.Comment{Body: req.Params["comment"]})
	}
	summary := fmt.Sprintf("Incident: %d:%s", req.Inc.Id, req.Inc.Name)
	project := req.Params["project"]
	if project == "" {
		project = j.project
	}
	i := jira.Issue{
		Fields: &jira.IssueFields{
			Description: req.Params["description"],
			Type: jira.IssueType{
				Name: "Task",
			},
			Project: jira.Project{
				Key: project,
			},
			Summary: summary,
			Labels:  []string{label},
		},
	}
	issue, err := j.client.Create(&i)
	if err != nil {
		return err
	}
	req.Rem.TaskId = issue.Key
	return nil
}

func (j *JiraEscalator) LoadTask(task *Task) error {
	if task.ID == "" {
		return fmt.Errorf("LoadTask requires a task ID")
	}
	issue, err := j.client.GetIssue(task.ID)
	if err != nil {
		return err
	}
	status := TaskStatusOther
	if in(issue.Fields.Status.Name, openJiraStates) {
		status = TaskStatusOpen
	} else if in(issue.Fields.Status.Name, closedJiraStates) {
		status = TaskStatusClosed
	}
	task.Status = status
	task.Created = time.Time(issue.Fields.Created)
	return nil
}
