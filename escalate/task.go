package escalate

import (
	"fmt"
	"sort"
	"time"

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
	ID, Title string
	Status    TaskStatus
	Created   time.Time
	Params    map[string]string
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

type TaskEscalator interface {
	CreateTask(task *Task) error
	UpdateTask(task *Task) error
	LoadTask(task *Task) error
}

type jiraClienter interface {
	AddComment(string, *jira.Comment) error
	Create(*jira.Issue) (*jira.Issue, error)
	GetIssue(string) (*jira.Issue, error)
	UpdateIssue(string, map[string]interface{}) error
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

func (c *jiraClient) UpdateIssue(issueKey string, data map[string]interface{}) error {
	_, err := c.Client.Issue.UpdateIssue(issueKey, data)
	return err
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

func (j *JiraEscalator) taskToIssue(task *Task) (*jira.Issue, error) {
	if task.Title == "" {
		return nil, fmt.Errorf("Task Title Required for JIRA task")
	}
	project := task.Params["project"]
	if project == "" {
		project = j.project
	}
	i := &jira.Issue{
		Fields: &jira.IssueFields{
			Type: jira.IssueType{
				Name: "Task",
			},
			Project: jira.Project{
				Key: project,
			},
			Summary: task.Title,
			Labels:  []string{label},
		},
	}
	if desc, ok := task.Params["description"]; ok {
		i.Fields.Description = desc
	}
	return i, nil
}

func (j *JiraEscalator) CreateTask(task *Task) error {
	i, err := j.taskToIssue(task)
	if err != nil {
		return err
	}
	issue, err := j.client.Create(i)
	if err != nil {
		return err
	}
	task.ID = issue.Key
	return j.LoadTask(task)
}

func (j *JiraEscalator) UpdateTask(task *Task) error {
	if task.ID == "" {
		return fmt.Errorf("UpdateTask requires a task ID")
	}
	if comment, ok := task.Params["comment"]; ok {
		return j.client.AddComment(task.ID, &jira.Comment{Body: comment})
	}
	data := make(map[string]interface{})
	for k, v := range task.Params {
		data[k] = v
	}
	d := map[string]interface{}{"fields": data}
	return j.client.UpdateIssue(task.ID, d)
}

func (j *JiraEscalator) LoadTask(task *Task) error {
	if task.ID == "" {
		return fmt.Errorf("LoadTask requires a task ID")
	}
	issue, err := j.client.GetIssue(task.ID)
	if err != nil {
		return err
	}
	task.Title = issue.Fields.Summary
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
