package remediator

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"github.com/golang/glog"
	"github.com/jmoiron/sqlx"
	"net"
	"time"
)

var schema = `
  CREATE TABLE IF NOT EXISTS remediations (
	id SERIAL PRIMARY KEY,
	status SMALLINT NOT NULL,
	alert_name VARCHAR(128) NOT NULL,
	entities VARCHAR(128)[] DEFAULT array[]::varchar[],
	start_time BIGINT NOT NULL,
	end_time BIGINT);

  CREATE TABLE IF NOT EXISTS commands (
	id SERIAL PRIMARY KEY,
	remediation_id INT NOT NULL,
	command TEXT,
	retcode SMALLINT,
	logs TEXT,
	results JSONB);
  `

type Dbase interface {
	NewTx() Txn
	Close() error
}

type DB struct {
	*sqlx.DB
}

func (d *DB) NewTx() Txn {
	tx := d.DB.MustBegin()
	return &Tx{tx}
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

type Txn interface {
	Rollback() error
	Commit() error
}

type Tx struct {
	*sqlx.Tx
}

func (tx *Tx) InQuery(query string, arg ...interface{}) error {
	query, args, err := sqlx.In(query, arg...)
	if err != nil {
		return err
	}
	query = tx.Rebind(query)
	return tx.Exec(query, args...)
}

func (tx *Tx) InSelect(query string, to interface{}, arg ...interface{}) error {
	query, args, err := sqlx.In(query, arg...)
	if err != nil {
		return err
	}
	query = tx.Rebind(query)
	return tx.Select(to, query, args...)
}

func (tx *Tx) Exec(query string, args ...interface{}) error {
	_, err := tx.Tx.Exec(query, args...)
	return err
}

// WithTx wraps a transaction around a function call.
func WithTx(ctx context.Context, tx Txn, cb func(ctx context.Context, tx Txn) error) error {
	err := cb(ctx, tx)
	if err != nil {
		tx.Rollback()
	} else {
		tx.Commit()
	}
	return err
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

type Status int

const (
	Status_ACTIVE             Status = 1
	Status_MONITORING         Status = 2
	Status_AUDIT_FAILED       Status = 3
	Status_REMEDIATION_FAILED Status = 4
	Status_ONCLEAR_FAILED     Status = 5
	Status_COMPLETED          Status = 6
	Status_ERROR              Status = 7
)

var statusMap = map[string]Status{
	"active":             Status_ACTIVE,
	"monitoring":         Status_MONITORING,
	"audit_failed":       Status_AUDIT_FAILED,
	"remediation_failed": Status_REMEDIATION_FAILED,
	"onclear_failed":     Status_ONCLEAR_FAILED,
	"completed":          Status_COMPLETED,
	"error":              Status_ERROR,
}

type Remediation struct {
	Status    Status
	AlertName string `db:"alert_name"`
	Entities  []string
	StartTime MyTime `db:"start_time"`
	EndTime   MyTime `db:"end_time"`
}

func (r *Remediation) End(status Status) {
	r.Status = status
	r.EndTime = MyTime{time.Now()}
}

func NewRemediation(alertName string, entities []string) *Remediation {
	return &Remediation{
		Status:    Status_ACTIVE,
		AlertName: alertName,
		Entities:  entities,
		StartTime: MyTime{time.Now()},
	}
}
