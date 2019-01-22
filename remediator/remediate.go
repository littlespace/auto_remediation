package remediator

import (
	"context"
	"fmt"
	"github.com/golang/glog"
	"github.com/mayuresh82/auto_remediation/executor"
	"sync"
	"time"
)

type Remediator struct {
	config   *ConfigHandler
	queue    executor.IncidentQueue
	executor executor.Executioner
	db       Dbase
	recv     chan executor.Incident
	remCache map[string]*Remediation

	sync.Mutex
}

func NewRemediator(configFile string) (*Remediator, error) {
	c, err := NewConfig(configFile)
	if err != nil {
		glog.Exitf("Failed to read config: %v", err)
	}
	config := c.Config
	q, err := executor.NewQueue(config.AmqpQName, config.AmqpAddr, config.AmqpUser, config.AmqpPass)
	if err != nil {
		return nil, err
	}
	recv := make(chan executor.Incident)
	q.Register(recv)
	//db := NewDB(config.DbAddr, config.DbUsername, config.DbPassword, config.DbName, config.DbTimeout)
	return &Remediator{
		config:   c,
		queue:    q,
		executor: executor.NewExecutor(config.ScriptsPath),
		db:       nil,
		recv:     recv,
		remCache: make(map[string]*Remediation),
	}, nil
}

func (r *Remediator) Start(ctx context.Context) {
	glog.Infof("Waiting for incidents")
	for {
		select {
		case newIncident := <-r.recv:
			// dont process incidents that have timed out
			if time.Now().Sub(newIncident.AddedAt) >= r.config.Config.Timeout {
				glog.V(2).Infof("Not processing timed out incident: %d:%s", newIncident.Id, newIncident.Name)
				continue
			}
			go r.processIncident(ctx, newIncident)
		case <-ctx.Done():
			return
		}
	}
}

func checkExecResults(rem *Remediation, itype string, results map[string]*executor.CmdResult) bool {
	for name, result := range results {
		glog.V(4).Infof("%s Logs:\n %v", name, result.Stderr)
		glog.V(4).Infof("%s output:\n %v", name, result.Stdout)
		// TODO : Save the result to DB
		if result.RetCode != 0 || result.Error != nil {
			glog.V(2).Infof("Cmd %s failed with retcode %d and error %v", name, result.RetCode, result.Error)
			glog.V(2).Infof("%s failed for incident %s", itype, rem.AlertName)
			statusStr := fmt.Sprintf("%s_failed", itype)
			rem.End(statusMap[statusStr])
			return false
		}
	}
	return true
}

func getCmds(incident executor.Incident, inCmds []executor.Command) []executor.Command {
	var cmds []executor.Command
	for _, cmd := range inCmds {
		cmds = append(cmds, executor.Command{
			Name:    cmd.Name,
			Command: cmd.Command,
			Args:    cmd.Args,
			Timeout: cmd.Timeout,
			Input:   incident.Infos,
		})
	}
	return cmds
}

func (r *Remediator) processIncident(ctx context.Context, incident executor.Incident) {
	glog.V(2).Infof("Processing incident: %s:%d", incident.Name, incident.Id)
	config := r.config.Config
	isActive := assertStatus("ACTIVE", config.AlertManagerAddr, incident.Id, config.AlertCheckInterval, config.AlertUpCheckCount)
	if !isActive {
		glog.V(2).Infof("Alert %d is not ACTIVE, skip remediation run", incident.Id)
		return
	}
	glog.V(2).Infof("Incident %s is active, proceeding with remediation", incident.Name)
	var entities []string
	for _, info := range incident.Infos {
		ent := info.Entity
		if info.Device != "" {
			ent = fmt.Sprintf("%s:%s", info.Device, info.Entity)
		}
		entities = append(entities, ent)
	}
	rem := NewRemediation(incident.Name, entities)
	// TODO save to DB
	// run pre-audits
	rule, ok := r.config.RuleByName(incident.Name)
	if !ok {
		glog.Errorf("No rule defined for Incident %s", incident.Name)
		rem.End(Status_ERROR)
		return
	}
	if !rule.Enabled {
		glog.Errorf("Rule %s defined but not enabled", rule.AlertName)
		rem.End(Status_ERROR)
		return
	}
	cmds := getCmds(incident, rule.Audits)
	results := r.executor.Execute(ctx, cmds, len(cmds))
	if !checkExecResults(rem, "audit", results) {
		return
	}
	// run remediations
	postAck(config.AlertManagerAddr, incident.Id, config.AmUsername, config.AmPassword)
	cmds = getCmds(incident, rule.Remediations)
	results = r.executor.Execute(ctx, cmds, len(cmds))
	if !checkExecResults(rem, "remediation", results) {
		return
	}
	// monitor until issue clears - potentially long wait
	rem.Status = Status_MONITORING
	checkCount := int(rule.ClearCheckTimeout / config.AlertCheckInterval)
	glog.V(2).Infof("Monitoring incident %d for %v", incident.Id, rule.ClearCheckTimeout)
	hasCleared := waitOnStatus("CLEARED", config.AlertManagerAddr, incident.Id, config.AlertCheckInterval, checkCount)
	if !hasCleared {
		glog.V(2).Infof("Alert %d not clear after %v, skip on-clear run", incident.Id, rule.ClearCheckTimeout)
		rem.End(Status_COMPLETED)
		return
	}
	// run on-clear
	glog.V(2).Infof("Incident %d has now cleared", incident.Id)
	if len(rule.OnClear) == 0 {
		rem.End(Status_COMPLETED)
		return
	}
	cmds = getCmds(incident, rule.OnClear)
	r.executor.Execute(ctx, cmds, len(cmds))
	if !checkExecResults(rem, "onclear", results) {
		return
	}
	rem.End(Status_COMPLETED)
}
