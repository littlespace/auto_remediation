package remediator

import (
	"fmt"
	"github.com/mayuresh82/auto_remediation/executor"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"path/filepath"
	"time"
)

type Config struct {
	AmqpQName          string        `yaml:"amqp_qname"`
	AmqpAddr           string        `yaml:"amqp_addr"`
	AmqpUser           string        `yaml:"amqp_user"`
	AmqpPass           string        `yaml:"amqp_pass"`
	AlertManagerAddr   string        `yaml:"alert_manager_addr"`
	AlertCheckInterval time.Duration `yaml:"alert_check_interval"`
	AlertUpCheckCount  int           `yaml:"alert_up_check_count"`
	AmUsername         string        `yaml:"am_username"`
	AmPassword         string        `yaml:"am_password"`
	ScriptsPath        string        `yaml:"scripts_path"`
	Timeout            time.Duration
	DbAddr             string        `yaml:"db_addr"`
	DbName             string        `yaml:"db_name"`
	DbUsername         string        `yaml:"db_username"`
	DbPassword         string        `yaml:"db_password"`
	DbTimeout          time.Duration `yaml:"db_timeout"`
}

type Rule struct {
	AlertName         string `yaml:"alert_name"`
	Enabled           bool
	ClearCheckTimeout time.Duration `yaml:"clear_check_timeout"`
	Audits            []executor.Command
	Remediations      []executor.Command
	OnClear           []executor.Command
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
			return rule, true
		}
	}
	return Rule{}, false
}
