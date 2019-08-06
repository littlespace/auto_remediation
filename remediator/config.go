package remediator

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/mayuresh82/auto_remediation/executor"
	"gopkg.in/yaml.v2"
)

const defaultRuleAttempts = 2

type Config struct {
	AdminUser          string        `yaml:"admin_user"`
	AdminPass          string        `yaml:"admin_pass"`
	AmqpQName          string        `yaml:"amqp_qname"`
	AmqpAddr           string        `yaml:"amqp_addr"`
	AmqpUser           string        `yaml:"amqp_user"`
	AmqpPass           string        `yaml:"amqp_pass"`
	AlertManagerAddr   string        `yaml:"alert_manager_addr"`
	AlertCheckInterval time.Duration `yaml:"alert_check_interval"`
	AmToken            string        `yaml:"am_token"`
	AmUsername         string        `yaml:"am_username"`
	AmPassword         string        `yaml:"am_password"`
	AmOwner            string        `yaml:"am_owner"`
	AmTeam             string        `yaml:"am_team"`
	ScriptsPath        string        `yaml:"scripts_path"`
	CommonOpts         string        `yaml:"common_opts_file"`
	IncidentTimeout    time.Duration `yaml:"incident_timeout"`
	DbAddr             string        `yaml:"db_addr"`
	DbName             string        `yaml:"db_name"`
	DbUsername         string        `yaml:"db_username"`
	DbPassword         string        `yaml:"db_password"`
	DbTimeout          time.Duration `yaml:"db_timeout"`
	SlackUrl           string        `yaml:"slack_url"`
	SlackChannel       string        `yaml:"slack_channel"`
	SlackMention       string        `yaml:"slack_mention"`
	JiraUrl            string        `yaml:"jira_url"`
	JiraUser           string        `yaml:"jira_username"`
	JiraPass           string        `yaml:"jira_password"`
	JiraProject        string        `yaml:"jira_project"`
}

type Rule struct {
	AlertName       string `yaml:"alert_name"`
	Enabled         bool
	UpCheckDuration time.Duration `yaml:"up_check_duration"`
	DontEscalate    bool          `yaml:"dont_escalate"`
	JiraProject     string        `yaml:"jira_project"`
	Attempts        int
	Audits          []executor.Command
	Remediations    []executor.Command
	OnClear         []executor.Command `yaml:"on_clear"`
}

type ConfigHandler struct {
	Config Config
	Rules  []Rule
}

func NewConfig(file string) (*ConfigHandler, error) {
	absPath, _ := filepath.Abs(file)
	c := &ConfigHandler{}
	data, err := ioutil.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("Unable to read config file: %v", err)
	}
	err = yaml.Unmarshal(data, c)
	if err != nil {
		return nil, fmt.Errorf("Unable to decode yaml: %v", err)
	}
	return c, nil
}

func (c *ConfigHandler) RuleByName(name string) (Rule, bool) {
	for _, rule := range c.Rules {
		if rule.AlertName == name {
			if rule.Attempts == 0 {
				rule.Attempts = defaultRuleAttempts
			}
			return rule, true
		}
	}
	return Rule{}, false
}

func (c *ConfigHandler) AdminCreds() (string, string) {
	return c.Config.AdminUser, c.Config.AdminPass
}
