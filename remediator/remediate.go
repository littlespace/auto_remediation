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
	esc      Escalator
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
		executor: executor.NewExecutor(config.ScriptsPath, config.CommonOpts),
		db:       db,
		am:       am,
		recv:     recv,
		exe:      make(map[int64]chan struct{}),
	}
	if config.SlackUrl != "" {
		r.notif = &SlackNotifier{Url: config.SlackUrl, Channel: config.SlackChannel, Mention: config.SlackMention}
	}
	if config.JiraUrl != "" {
		r.esc = NewJiraEscalator(config.JiraUrl, config.JiraUser, config.JiraPass, config.JiraProject)
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

func (r *Remediator) notify(rem *Remediation, msg string) {
	if r.notif != nil {
		r.notif.Send(rem, msg)
	}
}

func (r *Remediator) escalate(rem *Remediation, inc executor.Incident, rule Rule, exeResults []*Command) {
	if r.esc == nil || rule.DontEscalate {
		return
	}
	params := map[string]string{"project": rule.JiraProject, "description": "", "comment": ""}
	if inc.Type == "CLEARED" {
		params["comment"] = "This incident has now CLEARED"
	}
	if rule.JiraProject == "" {
		params["project"] = r.config.Config.JiraProject
	}
	for _, exeRes := range exeResults {
		params["description"] += fmt.Sprintf("%s Output: \n%s\n\n", exeRes.Command, exeRes.Results)
	}
	if params["description"] != "" {
		params["comment"] += "\n" + params["description"]
	}
	req := &EscalationRequest{rem: rem, inc: inc, params: params}
	if err := r.esc.Escalate(req); err != nil {
		glog.Errorf("Failed to escalate rem %d / inc %d : %v", rem.Id, inc.Id, err)
	}
	if err := r.db.UpdateRecord(rem); err != nil {
		glog.Errorf("Failed to update rem in db: %v", err)
	}
}

func (r *Remediator) execute(rem *Remediation, itype string, cmds []executor.Command) ([]*Command, bool) {
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
	var ret []*Command
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
		ret = append(ret, c)
		if _, err := r.db.NewRecord(c); err != nil {
			glog.Errorf("Failed to save cmd to db: %v", err)
		}
		if result.RetCode != 0 {
			glog.V(2).Infof("Cmd %s failed with retcode %d and error %v", cmd.Name, result.RetCode, result.Error)
			glog.V(2).Infof("%s failed for incident %s", itype, rem.IncidentName)
			statusStr := fmt.Sprintf("%s_failed", itype)
			rem.End(statusMap[statusStr], r.db)
			return ret, false
		}
		if result.Error != nil {
			errStr := fmt.Sprintf("Failed to run cmd %s: %v", cmd.Name, result.Error)
			glog.V(2).Infof(errStr)
			rem.End(Status_ERROR, r.db)
			c.Results = errStr
			return ret, false
		}
	}
	return ret, true
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
	if incident.IsAggregate {
		url := fmt.Sprintf("%s?agg_id=%d", alertPath, incident.Id)
		components, err := r.am.getAlerts(url)
		if err != nil {
			glog.Errorf("Failed to query components for incident %d", incident.Id)
			return nil
		}
		incident.Data["components"] = components
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

func (r *Remediator) checkExisting(incident executor.Incident, rule Rule) (*Remediation, bool) {
	rem := NewRemediation(incident)
	existing, err := r.db.GetRemediation(QueryRemByIncidentId, rem.IncidentId)
	if existing == nil || err != nil {
		return rem, false
	}
	glog.Infof("Found existing remediation %d (%v) for incident %d:%s", existing.Id, rem.Status, incident.Id, incident.Name)
	if existing.Status == Status_REMEDIATION_SUCCESS {
		// TODO Provide a way to re-run the remediation if required (from task ?)
		return existing, true
	}
	if existing.Attempts < rule.Attempts {
		return existing, false
	}
	return existing, true
}

func (r *Remediator) processActive(incident executor.Incident, rule Rule) *Remediation {
	rem, done := r.checkExisting(incident, rule)
	if done {
		return rem
	}
	config := r.config.Config
	isActive := r.am.assertStatus("ACTIVE", incident.Id, config.AlertCheckInterval, rule.UpCheckDuration)
	if !isActive {
		glog.V(2).Infof("Alert %d is not ACTIVE, skip remediation run", incident.Id)
		return nil
	}
	glog.V(2).Infof("Incident %s is active, proceeding with remediation", incident.Name)
	if rem.Id == 0 {
		newId, err := r.db.NewRecord(rem)
		if err != nil {
			glog.Errorf("Failed to save remediation to db: %v", err)
		}
		glog.Infof("Created new remediation %d for incident %d", newId, incident.Id)
		rem.Id = newId
	}
	rem.Attempts += 1
	// run pre-audits
	cmds := getCmds(incident, rule.Audits)
	exeResults, passed := r.execute(rem, "audit", cmds)
	if !passed {
		glog.Errorf("Audit run failed, not running remediations")
		r.notify(rem, "Audit run failed, not running remediations")
		r.escalate(rem, incident, rule, exeResults)
		return rem
	}
	// run remediations
	r.am.postAck(incident.Id)
	cmds = getCmds(incident, rule.Remediations)
	exeResults, passed = r.execute(rem, "remediation", cmds)
	if !passed {
		glog.Errorf("Remediation run failed")
		r.notify(rem, "Remediation run failed")
	} else {
		rem.End(Status_REMEDIATION_SUCCESS, r.db)
		r.notify(rem, "Remediation Successful")
	}
	r.escalate(rem, incident, rule, exeResults)
	return rem
}

func (r *Remediator) processCleared(incident executor.Incident, rule Rule) *Remediation {
	// run on-clear
	glog.V(2).Infof("Incident %d has now cleared", incident.Id)
	rem, err := r.db.GetRemediation(QueryRemByIncidentId, incident.Id)
	if rem == nil || err != nil {
		glog.V(2).Infof("Cant find remediation for incident %d", incident.Id)
		return nil
	}
	var (
		exeResults []*Command
		passed     bool
	)
	defer r.escalate(rem, incident, rule, exeResults)
	if len(rule.OnClear) == 0 {
		glog.V(2).Infof("Nothing to do for incident %d clear", incident.Id)
		return nil
	}
	if rem.Status != Status_REMEDIATION_SUCCESS {
		glog.V(2).Infof("Remediation %d for incident %d was not successful, skip onclear run", rem.Id, incident.Id)
		return rem
	}
	cmds := getCmds(incident, rule.OnClear)
	exeResults, passed = r.execute(rem, "onclear", cmds)
	if passed {
		rem.End(Status_ONCLEAR_SUCCESS, r.db)
		r.notify(rem, "Incident cleared")
	}
	return rem
}
