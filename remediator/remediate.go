package remediator

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/golang/glog"
	am "github.com/mayuresh82/auto_remediation/alert_manager"
	"github.com/mayuresh82/auto_remediation/escalate"
	"github.com/mayuresh82/auto_remediation/executor"
	"github.com/mayuresh82/auto_remediation/models"
	"github.com/mayuresh82/auto_remediation/notify"
)

type Remediator struct {
	Config   *ConfigHandler
	Db       models.Dbase
	queue    executor.IncidentQueue
	executor executor.Executioner
	am       *am.AlertManager
	notif    notify.Notifier
	esc      escalate.TaskEscalator
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
	db := models.NewDB(config.DbAddr, config.DbUsername, config.DbPassword, config.DbName, config.DbTimeout)
	amgr := am.NewAlertManager(config.AlertManagerAddr, config.AmUsername, config.AmPassword, config.AmOwner, config.AmTeam)
	r := &Remediator{
		Config:   c,
		Db:       db,
		queue:    q,
		executor: executor.NewExecutor(config.ScriptsPath, config.CommonOpts),
		am:       amgr,
		recv:     recv,
		exe:      make(map[int64]chan struct{}),
	}
	if config.SlackUrl != "" {
		r.notif = &notify.SlackNotifier{Url: config.SlackUrl, Channel: config.SlackChannel, Mention: config.SlackMention}
	}
	if config.JiraUrl != "" {
		esc, err := escalate.NewJiraEscalator(config.JiraUrl, config.JiraUser, config.JiraPass, config.JiraProject)
		if err != nil {
			return nil, err
		}
		r.esc = esc
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
			Input:   &incident,
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
			if time.Now().Sub(newIncident.AddedAt) >= r.Config.Config.IncidentTimeout {
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
	r.Db.Close()
}

func (r *Remediator) notify(rem *models.Remediation, msg string) {
	if r.notif != nil {
		r.notif.Send(rem, msg)
	}
}

func (r *Remediator) newTask(inc *executor.Incident, rule Rule) *escalate.Task {
	t := &escalate.Task{}
	t.Title = fmt.Sprintf("Incident: %d:%s", inc.Id, inc.Name)
	t.Params = map[string]string{"project": rule.JiraProject}
	if r.esc == nil || rule.DontEscalate {
		return t
	}
	if err := r.esc.CreateTask(t); err != nil {
		glog.Errorf("Failed to open task: %v", err)
	}
	return t
}

func (r *Remediator) updateTask(task *escalate.Task, inc executor.Incident, exeResults models.Commands, new bool) {
	if r.esc == nil || task.ID == "" {
		return
	}
	content := ""
	if inc.Type == "CLEARED" {
		content += "This incident has now CLEARED"
	}
	content += "\n" + exeResults.String()
	if new {
		task.Params = map[string]string{"description": content}
	} else {
		task.Params = map[string]string{"comment": content}
	}
	if err := r.esc.UpdateTask(task); err != nil {
		glog.Errorf("Failed to update task %s: %v", task.ID, err)
	}
}

func (r *Remediator) execute(rem *models.Remediation, itype string, cmds []executor.Command) (models.Commands, bool) {
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
	var ret models.Commands
	for cmd, result := range results {
		glog.V(4).Infof("%s Logs:\n %v", cmd.Name, result.Stderr)
		glog.V(4).Infof("%s output:\n %v", cmd.Name, result.Stdout)
		c := &models.Command{
			RemediationId: rem.Id,
			Command:       cmd.Command,
			Retcode:       result.RetCode,
			Logs:          result.Stderr,
			Results:       result.Stdout,
			Runtime:       int64(result.Runtime.Seconds()),
		}
		ret = append(ret, c)
		if _, err := r.Db.NewRecord(c); err != nil {
			glog.Errorf("Failed to save cmd to db: %v", err)
		}
		if result.RetCode != 0 {
			glog.V(2).Infof("Cmd %s failed with retcode %d and error %v", cmd.Name, result.RetCode, result.Error)
			glog.V(2).Infof("%s failed for incident %s", itype, rem.IncidentName)
			statusStr := fmt.Sprintf("%s_failed", itype)
			rem.End(models.StatusMap[statusStr], r.Db)
			return ret, false
		}
		if result.Error != nil {
			errStr := fmt.Sprintf("Failed to run cmd %s: %v", cmd.Name, result.Error)
			glog.V(2).Infof(errStr)
			rem.End(models.Status_ERROR, r.Db)
			c.Results = errStr
			return ret, false
		}
	}
	return ret, true
}

func (r *Remediator) processIncident(incident executor.Incident) *models.Remediation {
	glog.V(2).Infof("Processing incident: %s:%d", incident.Name, incident.Id)
	rule, ok := r.Config.RuleByName(incident.Name)
	if !ok {
		glog.Errorf("No rule defined for Incident %s", incident.Name)
		return nil
	}
	if !rule.Enabled {
		glog.Errorf("Rule %s defined but not enabled", rule.AlertName)
		return nil
	}
	if incident.IsAggregate {
		url := fmt.Sprintf("%s?agg_id=%d", am.AlertPath, incident.Id)
		components, err := r.am.GetAlerts(url)
		if err != nil {
			glog.Errorf("Failed to query components for incident %d", incident.Id)
			return nil
		}
		incident.Data["components"] = components
	}
	var rem *models.Remediation
	switch incident.Type {
	case "ACTIVE":
		rem = r.processActive(incident, rule)
	case "CLEARED":
		rem = r.processCleared(incident, rule)
	}
	return rem
}

func (r *Remediator) remediationForIncident(incident executor.Incident) *models.Remediation {
	rem := models.NewRemediation(incident)
	existing, err := r.Db.GetRemediations(models.QueryRemByIncidentId, rem.IncidentId)
	if err != nil {
		glog.Errorf("Failed to get remediations: %v", err)
		return nil
	}
	if len(existing) == 0 {
		existing, err = r.Db.GetRemediations(models.QueryRemByNameEntity, rem.IncidentName, []string(rem.Entities))
		if err != nil {
			glog.Errorf("Failed to get remediations: %v", err)
			return nil
		}
		if len(existing) == 0 {
			return nil
		}
	}
	sort.Slice(existing, func(i, j int) bool {
		return existing[i].StartTime.After(existing[j].StartTime.Time)
	})
	var current *models.Remediation
	// pick the most recent open task
	var tasks escalate.Tasks
	for _, rem := range existing {
		task := &escalate.Task{ID: rem.TaskId}
		if err := r.esc.LoadTask(task); err != nil {
			glog.Errorf("Failed to load task: %s : %v", rem.TaskId, err)
			continue
		}
		if task.Status == escalate.TaskStatusOpen {
			tasks = append(tasks, task)
		}
	}
	latest := tasks.Latest()
	if latest != nil {
		for _, rem := range existing {
			if rem.TaskId == latest.ID {
				current = rem
				break
			}
		}
	}
	return current
}

func (r *Remediator) checkExisting(incident executor.Incident, rule Rule) (*models.Remediation, bool) {
	current := r.remediationForIncident(incident)
	if current == nil {
		return nil, false
	}
	glog.Infof("Found existing remediation %d (%v) for incident %d:%s", current.Id, current.Status.String(), incident.Id, incident.Name)
	if current.Status == models.Status_REMEDIATION_SUCCESS {
		// TODO Provide a way to re-run the remediation if required (from task ?)
		return current, true
	}
	if current.Status.IsFailed() {
		if current.Attempts < rule.Attempts {
			return current, false
		}
		glog.V(2).Infof("Remediation for incident %d reached max attempts", incident.Id)
	}
	return current, true
}

func (r *Remediator) processActive(incident executor.Incident, rule Rule) *models.Remediation {
	// check if an existing remediation has taken place for the incident
	rem, done := r.checkExisting(incident, rule)
	if done {
		r.am.PostAck(incident.Id)
		return rem
	}
	if rem == nil {
		rem = models.NewRemediation(incident)
	}
	// make sure the incident stays active for the UpCheckDuration
	config := r.Config.Config
	isActive := r.am.AssertStatus("ACTIVE", incident.Id, config.AlertCheckInterval, rule.UpCheckDuration)
	if !isActive {
		glog.V(2).Infof("Alert %d is not ACTIVE, skip remediation run", incident.Id)
		return nil
	}
	glog.V(2).Infof("Incident %s is active, proceeding with remediation", incident.Name)
	// create new remedation in DB if none exists
	if rem.Id == 0 {
		newId, err := r.Db.NewRecord(rem)
		if err != nil {
			glog.Errorf("Failed to save remediation to db: %v", err)
		}
		glog.Infof("Created new remediation %d for incident %d", newId, incident.Id)
		rem.Id = newId
	}
	// if an existing failed remediation/task exists, try another attempt. Else, create a new task
	rem.Attempts += 1
	task := &escalate.Task{}
	if rem.TaskId == "" {
		task = r.newTask(&incident, rule)
	} else {
		task.ID = rem.TaskId
	}
	incident.Data["task_id"] = task.ID
	defer func() {
		rem.TaskId = task.ID
		if err := r.Db.UpdateRecord(rem); err != nil {
			glog.Errorf("Failed to update rem in db: %v", err)
		}
	}()
	// run pre-audits
	cmds := getCmds(incident, rule.Audits)
	exeResults, passed := r.execute(rem, "audit", cmds)
	if !passed {
		glog.Errorf("Audit run failed, not running remediations")
		r.notify(rem, "Audit run failed, not running remediations")
		r.updateTask(task, incident, exeResults, rem.TaskId == "")
		return rem
	}
	// run remediations
	cmds = getCmds(incident, rule.Remediations)
	exeResults, passed = r.execute(rem, "remediation", cmds)
	if !passed {
		glog.Errorf("Remediation run failed")
		r.notify(rem, "Remediation run failed")
	} else {
		rem.End(models.Status_REMEDIATION_SUCCESS, r.Db)
		r.notify(rem, "Remediation Successful")
	}
	r.am.PostAck(incident.Id)
	r.updateTask(task, incident, exeResults, rem.TaskId == "")
	return rem
}

func (r *Remediator) processCleared(incident executor.Incident, rule Rule) *models.Remediation {
	glog.V(2).Infof("Incident %d has now cleared", incident.Id)
	rem := r.remediationForIncident(incident)
	if rem == nil {
		glog.V(2).Infof("Cant find remediation for incident %d", incident.Id)
		return nil
	}
	var (
		exeResults models.Commands
		passed     bool
	)
	task := &escalate.Task{ID: rem.TaskId}
	defer func() {
		r.updateTask(task, incident, exeResults, false)
	}()
	if len(rule.OnClear) == 0 {
		glog.V(2).Infof("Nothing to do for incident %d clear", incident.Id)
		return nil
	}
	if rem.Status != models.Status_REMEDIATION_SUCCESS {
		glog.V(2).Infof("Remediation %d for incident %d was not successful, skip onclear run", rem.Id, incident.Id)
		return rem
	}
	// run on-clear
	cmds := getCmds(incident, rule.OnClear)
	exeResults, passed = r.execute(rem, "onclear", cmds)
	if passed {
		rem.End(models.Status_ONCLEAR_SUCCESS, r.Db)
		r.notify(rem, "Incident cleared")
	}
	return rem
}
