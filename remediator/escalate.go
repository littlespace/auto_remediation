package remediator

import (
	"fmt"
	"github.com/mayuresh82/auto_remediation/executor"
	jira "gopkg.in/andygrunwald/go-jira.v1"
)

const label = "auto-remediated"

type EscalationRequest struct {
	rem    *Remediation
	inc    executor.Incident
	params map[string]string
}

type Escalator interface {
	Escalate(req *EscalationRequest) error
}

type JiraEscalator struct {
	url     string
	project string
	tp      jira.BasicAuthTransport
}

func NewJiraEscalator(url, user, pass, project string) *JiraEscalator {
	return &JiraEscalator{
		url:     url,
		project: project,
		tp: jira.BasicAuthTransport{
			Username: user,
			Password: pass,
		},
	}
}

func (j *JiraEscalator) Escalate(req *EscalationRequest) error {
	jiraClient, err := jira.NewClient(j.tp.Client(), j.url)
	if err != nil {
		return err
	}
	if req.rem.TaskId != "" {
		_, _, err = jiraClient.Issue.AddComment(req.rem.TaskId, &jira.Comment{Body: req.params["comment"]})
		return err
	}
	summary := fmt.Sprintf("Incident: %d:%s", req.inc.Id, req.inc.Name)
	project := req.params["project"]
	if project == "" {
		project = j.project
	}
	i := jira.Issue{
		Fields: &jira.IssueFields{
			Description: req.params["description"],
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
	issue, _, err := jiraClient.Issue.Create(&i)
	if err != nil {
		return err
	}
	req.rem.TaskId = issue.Key
	return nil
}
