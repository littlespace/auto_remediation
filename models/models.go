package models

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/mayuresh82/auto_remediation/executor"
)

var schema = `
  CREATE TABLE IF NOT EXISTS remediations (
	id SERIAL PRIMARY KEY,
	status SMALLINT NOT NULL,
	incident_name VARCHAR(128) NOT NULL,
	incident_id INT NOT NULL,
	entities VARCHAR(128)[] DEFAULT array[]::varchar[],
	start_time BIGINT NOT NULL,
	end_time BIGINT,
	task_id VARCHAR(32),
	attempts INT);

  CREATE TABLE IF NOT EXISTS commands (
	id SERIAL PRIMARY KEY,
	remediation_id INT NOT NULL,
	command TEXT,
	retcode SMALLINT,
	runtime INT,
	logs TEXT,
	results TEXT);
  `

var (
	QueryInsertNewRemediation = `INSERT INTO
    remediations (
      incident_name, incident_id, status, entities, start_time, end_time, task_id, attempts
    ) VALUES (
	  :incident_name, :incident_id, :status, :entities, :start_time, :end_time, :task_id, :attempts
	) RETURNING id`
	QueryRemByIncidentId = "SELECT * FROM remediations WHERE incident_id=$1"
	QueryRemByNameEntity = "SELECT * FROM remediations WHERE incident_name=? AND entities @> ARRAY[?]::varchar[]"

	QueryUpdateRemById = `UPDATE remediations SET
	  incident_name=:incident_name, incident_id=:incident_id, status=:status,
	  entities=:entities, start_time=:start_time, end_time=:end_time, task_id=:task_id, attempts=:attempts
	WHERE id=:id`

	QueryInsertNewCmd = `INSERT INTO
	commands (
		remediation_id, command, retcode, runtime, logs, results
	) VALUES (
		:remediation_id, :command, :retcode, :runtime, :logs, :results
	) RETURNING id`
)

type Dbase interface {
	UpdateRecord(i interface{}) error
	NewRecord(i interface{}) (int64, error)
	GetRemediations(query string, args ...interface{}) ([]*Remediation, error)
	Query(table string, params map[string]interface{}) ([]interface{}, error)
	Close() error
}

type DB struct {
	*sqlx.DB
}

func NewDB(addr, username, password, dbName string, timeout time.Duration) Dbase {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		glog.Fatalf("Invalid DB addr: %s", addr)
	}
	if host == "" {
		host = "localhost"
	}
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s connect_timeout=%d sslmode=disable", host, port, username, password, dbName, timeout)
	db, err := sqlx.Open("postgres", connStr)
	if err != nil {
		glog.Fatalf("Cant open DB: %v", err)
	}
	db.MustExec(schema)
	return &DB{db}
}

func (db *DB) UpdateRecord(i interface{}) error {
	_, err := db.NamedExec(QueryUpdateRemById, i)
	return err
}

func (db *DB) NewRecord(i interface{}) (int64, error) {
	var newId int64
	var stmt *sqlx.NamedStmt
	var err error
	switch i.(type) {
	case *Remediation:
		stmt, err = db.PrepareNamed(QueryInsertNewRemediation)
	case *Command:
		stmt, err = db.PrepareNamed(QueryInsertNewCmd)
	}
	if err != nil {
		return newId, err
	}
	err = stmt.Get(&newId, i)
	return newId, err
}

func (db *DB) GetRemediations(query string, args ...interface{}) ([]*Remediation, error) {
	var rem []*Remediation
	var err error
	if strings.Contains(query, "?") {
		query, args, err = sqlx.In(query, args...)
		if err != nil {
			return nil, err
		}
		query = db.Rebind(query)
	}
	err = db.Select(&rem, query, args...)
	return rem, err
}

func (db *DB) Query(table string, params map[string]interface{}) ([]interface{}, error) {
	baseQ := fmt.Sprintf("SELECT * FROM %s", table)
	if len(params) > 0 {
		baseQ += " WHERE "
		c := 0
		for field := range params {
			baseQ += fmt.Sprintf("%s=:%s", field, field)
			if c < len(params)-1 {
				baseQ += " AND "
			}
			c++
		}
	}
	var items []interface{}
	query, args, err := sqlx.Named(baseQ, params)
	query = db.Rebind(query)
	switch table {
	case "remediations":
		var rems []*Remediation
		err = db.Select(&rems, query, args...)
		for _, r := range rems {
			items = append(items, r)
		}
	case "commands":
		var cmds []*Command
		err = db.Select(&cmds, query, args...)
		for _, c := range cmds {
			items = append(items, c)
		}
	}
	return items, err
}

type MyTime struct {
	time.Time
}

func (t MyTime) Value() (driver.Value, error) {
	return driver.Value(t.Unix()), nil
}

func (t *MyTime) Scan(src interface{}) error {
	ns := sql.NullInt64{}
	if err := ns.Scan(src); err != nil {
		return err
	}

	if !ns.Valid {
		return fmt.Errorf("MyTime.Scan: column is not nullable")
	}
	*t = MyTime{time.Unix(ns.Int64, 0)}
	return nil
}

type MyNullTime struct {
	pq.NullTime
}

func (t MyNullTime) Value() (driver.Value, error) {
	value, _ := t.NullTime.Value()
	if value == nil {
		return nil, nil
	}
	tm := value.(time.Time)
	mt := MyTime{tm}
	return mt.Value()
}

func (t *MyNullTime) Scan(src interface{}) error {
	mt := MyTime{}
	if err := mt.Scan(src); err != nil {
		return err
	}
	if !mt.Time.IsZero() {
		t.NullTime.Time = mt.Time
		t.NullTime.Valid = true
	}
	return nil
}

type Status int

func (s Status) String() string {
	for str, val := range StatusMap {
		if val == s {
			return str
		}
	}
	return "unknown"
}

const (
	Status_ACTIVE              Status = 1
	Status_AUDIT_FAILED        Status = 2
	Status_REMEDIATION_FAILED  Status = 3
	Status_REMEDIATION_SUCCESS Status = 4
	Status_ONCLEAR_FAILED      Status = 5
	Status_ONCLEAR_SUCCESS     Status = 6
	Status_ERROR               Status = 7
)

var StatusMap = map[string]Status{
	"active":              Status_ACTIVE,
	"audit_failed":        Status_AUDIT_FAILED,
	"remediation_failed":  Status_REMEDIATION_FAILED,
	"remediation_success": Status_REMEDIATION_SUCCESS,
	"onclear_failed":      Status_ONCLEAR_FAILED,
	"onclear_success":     Status_ONCLEAR_SUCCESS,
	"error":               Status_ERROR,
}

var StatusFailed = []Status{Status_AUDIT_FAILED, Status_REMEDIATION_FAILED}

func (s Status) IsFailed() bool {
	for _, status := range StatusFailed {
		if s == status {
			return true
		}
	}
	return false
}

type Remediation struct {
	Id           int64
	IncidentName string `db:"incident_name"`
	IncidentId   int64  `db:"incident_id"`
	Status       Status
	Entities     pq.StringArray
	StartTime    MyTime     `db:"start_time"`
	EndTime      MyNullTime `db:"end_time"`
	TaskId       string     `db:"task_id"`
	Attempts     int
}

func (r *Remediation) End(status Status, db Dbase) error {
	r.Status = status
	r.EndTime = MyNullTime{pq.NullTime{time.Now(), true}}
	err := db.UpdateRecord(r)
	if err != nil {
		glog.Errorf("Failed to update record: %v", err)
	}
	return err
}

func NewRemediation(incident executor.Incident) *Remediation {
	var entities []string
	if ents, ok := incident.Data["entities"]; ok {
		for _, ent := range ents.([]interface{}) {
			entities = append(entities, ent.(string))
		}
	} else if d, ok := incident.Data["device"]; ok {
		entities = append(entities, fmt.Sprintf("%v:%v", d, incident.Data["entity"]))
	} else {
		entities = append(entities, incident.Data["entity"].(string))
	}
	return &Remediation{
		Status:       Status_ACTIVE,
		IncidentName: incident.Name,
		IncidentId:   incident.Id,
		Entities:     pq.StringArray(entities),
		StartTime:    MyTime{time.Now()},
	}
}

type Command struct {
	Id            int64
	RemediationId int64 `db:"remediation_id"`
	Command       string
	Retcode       int
	Runtime       int64
	Logs          string
	Results       string
}
