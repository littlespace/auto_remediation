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
	am       *AlertManager
	notif    Notifier
	recv     chan executor.Incident
	exe      map[int64]chan struct{}
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
	db := NewDB(config.DbAddr, config.DbUsername, config.DbPassword, config.DbName, config.DbTimeout)
	am := NewAlertManager(config.AlertManagerAddr, config.AmUsername, config.AmPassword, config.AmOwner, config.AmTeam)
	r := &Remediator{
		config:   c,
		queue:    q,
		executor: executor.NewExecutor(config.ScriptsPath),
		db:       db,
		am:       am,
		recv:     recv,
		exe:      make(map[int64]chan struct{}),
	}
	if config.SlackUrl != "" {
		r.notif = &SlackNotifier{Url: config.SlackUrl, Channel: config.SlackChannel, Mention: config.SlackMention}
	}
	return r, nil
}

func getCmds(incident executor.Incident, inCmds []executor.Command) []executor.Command {
	var cmds []executor.Command
	for _, cmd := range inCmds {
		cmds = append(cmds, executor.Command{
			Name:    cmd.Name,
			Command: cmd.Command,
			Args:    cmd.Args,
			Timeout: cmd.Timeout,
			Input:   incident,
		})
	}
	return cmds
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
			go r.processIncident(newIncident)
		case <-ctx.Done():
			return
		}
	}
}

func (r *Remediator) Close() {
	r.Lock()
	defer r.Unlock()
	glog.Infof("Waiting for %d pending commands to finish executing", len(r.exe))
	for id, e := range r.exe {
		<-e
		glog.V(2).Infof("Done executing remediation %d", id)
	}
	r.db.Close()
}

func (r *Remediator) Notify(rem *Remediation, msg string) {
	if r.notif != nil {
		r.notif.Send(rem, msg)
	}
}

func (r *Remediator) execute(rem *Remediation, itype string, cmds []executor.Command) bool {
	glog.V(4).Infof("Running %s for remediation %d, incident %d", itype, rem.Id, rem.IncidentId)
	e := make(chan struct{})
	defer func() {
		close(e)
		r.Lock()
		delete(r.exe, rem.Id)
		r.Unlock()
	}()
	r.Lock()
	r.exe[rem.Id] = e
	r.Unlock()
	results := r.executor.Execute(context.Background(), cmds, len(cmds))
	for cmd, result := range results {
		glog.V(4).Infof("%s Logs:\n %v", cmd.Name, result.Stderr)
		glog.V(4).Infof("%s output:\n %v", cmd.Name, result.Stdout)
		c := &Command{
			RemediationId: rem.Id,
			Command:       cmd.Command,
			Retcode:       result.RetCode,
			Logs:          result.Stderr,
			Results:       result.Stdout,
		}
		if _, err := r.db.NewRecord(c); err != nil {
			glog.Errorf("Failed to save cmd to db: %v", err)
		}
		if result.RetCode != 0 {
			glog.V(2).Infof("Cmd %s failed with retcode %d and error %v", cmd.Name, result.RetCode, result.Error)
			glog.V(2).Infof("%s failed for incident %s", itype, rem.IncidentName)
			statusStr := fmt.Sprintf("%s_failed", itype)
			rem.End(statusMap[statusStr], r.db)
			return false
		}
		if result.Error != nil {
			glog.V(2).Infof("Failed to run cmd %s: %v", cmd.Name, result.Error)
			rem.End(Status_ERROR, r.db)
			return false
		}
	}
	return true
}

func (r *Remediator) processIncident(incident executor.Incident) *Remediation {
	glog.V(2).Infof("Processing incident: %s:%d", incident.Name, incident.Id)
	rule, ok := r.config.RuleByName(incident.Name)
	if !ok {
		glog.Errorf("No rule defined for Incident %s", incident.Name)
		return nil
	}
	if !rule.Enabled {
		glog.Errorf("Rule %s defined but not enabled", rule.AlertName)
		return nil
	}
	var rem *Remediation
	switch incident.Type {
	case "ACTIVE":
		rem = r.processActive(incident, rule)
	case "CLEARED":
		rem = r.processCleared(incident, rule)
	}
	return rem
}

func (r *Remediator) processActive(incident executor.Incident, rule Rule) *Remediation {
	config := r.config.Config
	isActive := r.am.assertStatus("ACTIVE", incident.Id, config.AlertCheckInterval, rule.UpCheckDuration)
	if !isActive {
		glog.V(2).Infof("Alert %d is not ACTIVE, skip remediation run", incident.Id)
		return nil
	}
	glog.V(2).Infof("Incident %s is active, proceeding with remediation", incident.Name)
	rem := NewRemediation(incident)
	newId, err := r.db.NewRecord(rem)
	if err != nil {
		glog.Errorf("Failed to save remediation to db: %v", err)
	}
	glog.Infof("Created new remediation %d for incident %d", newId, incident.Id)
	rem.Id = newId
	// run pre-audits
	cmds := getCmds(incident, rule.Audits)
	if !r.execute(rem, "audit", cmds) {
		glog.Errorf("Audit run failed, not running remediations")
		r.Notify(rem, "Audit run failed, not running remediations")
		return rem
	}
	// run remediations
	r.am.postAck(incident.Id)
	cmds = getCmds(incident, rule.Remediations)
	if !r.execute(rem, "remediation", cmds) {
		glog.Errorf("Remediation run failed")
		r.Notify(rem, "Remediation run failed")
		return rem
	}
	rem.End(Status_REMEDIATION_SUCCESS, r.db)
	r.Notify(rem, "Remediation Successful")
	return rem
}

func (r *Remediator) processCleared(incident executor.Incident, rule Rule) *Remediation {
	// run on-clear
	glog.V(2).Infof("Incident %d has now cleared", incident.Id)
	if len(rule.OnClear) == 0 {
		glog.V(2).Infof("Nothing to do for incident %d clear", incident.Id)
		return nil
	}
	cmds := getCmds(incident, rule.OnClear)
	rem, err := r.db.GetRemediation(QueryRemByIncidentId, incident.Id)
	if rem == nil || err != nil {
		glog.V(2).Info("Cant find remediation for incident %d", incident.Id)
		return nil
	}
	if rem.Status != Status_REMEDIATION_SUCCESS {
		glog.V(2).Infof("Remediation %d for incident %d was not successful, skip onclear run", rem.Id, incident.Id)
		return rem
	}
	if r.execute(rem, "onclear", cmds) {
		rem.End(Status_ONCLEAR_SUCCESS, r.db)
		r.Notify(rem, "Incident cleared")
	}
	return rem
}
