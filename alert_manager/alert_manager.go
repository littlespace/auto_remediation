package alert_manager

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang/glog"
)

const (
	AlertPath    = "/api/alerts"
	defaultOwner = "auto_remediator"
)

type Clienter interface {
	Do(req *http.Request) (*http.Response, error)
}

type Client struct {
	*http.Client
}

type AlertManager struct {
	addr   string
	owner  string
	team   string
	token  string
	Client Clienter

	sync.Mutex
}

func NewAlertManager(addr, user, pass, owner, team string) *AlertManager {
	a := &AlertManager{addr: addr, team: team, owner: owner}
	if a.owner == "" {
		a.owner = defaultOwner
	}
	a.Client = &Client{&http.Client{Timeout: 5 * time.Second}}
	if err := a.getToken(user, pass); err != nil {
		// TODO add retry logic here
		glog.Exitf("failed to talk to Alert Manager: %v", err)
	}
	return a
}

func (a *AlertManager) GetAlerts(url string) ([]map[string]interface{}, error) {
	u := a.addr + url
	req, _ := http.NewRequest("GET", u, nil)
	resp, err := a.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var data []interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("Unable to decode json body: %v", err)
	}
	var ret []map[string]interface{}
	for _, d := range data {
		ret = append(ret, d.(map[string]interface{}))
	}
	return ret, nil
}

func (a *AlertManager) GetStatus(id int64) (string, error) {
	url := fmt.Sprintf("%s?id=%d", AlertPath, id)
	alerts, err := a.GetAlerts(url)
	if err != nil {
		return "", fmt.Errorf("Failed to query alert %d: %v", id, err)
	}
	if len(alerts) == 0 {
		return "", fmt.Errorf("No alerts returned for ID %d", id)
	}
	return alerts[0]["status"].(string), nil
}

func (a *AlertManager) AssertStatus(desiredStatus string, id int64, checkInterval, checkTime time.Duration) bool {
	now := time.Now()
	for {
		status, err := a.GetStatus(id)
		if err != nil {
			glog.Errorf("Failed to check alert %d status: %v", id, err)
			return false
		}
		if status != desiredStatus {
			return false
		}
		if time.Now().Sub(now) >= checkTime {
			break
		}
		time.Sleep(checkInterval)
	}
	return true
}

func (a *AlertManager) WaitOnStatus(desiredStatus string, id int64, checkInterval, timeout time.Duration) bool {
	t := time.NewTimer(timeout)
	for {
		select {
		case <-t.C:
			return false
		default:
			status, err := a.GetStatus(id)
			if err != nil {
				glog.Errorf("Failed to check alert %d status: %v", id, err)
				return false
			}
			if status == desiredStatus {
				return true
			}
			time.Sleep(checkInterval)
		}
	}
	return false
}

func (a *AlertManager) getToken(user, pass string) error {
	url := a.addr + "/api/auth"
	data := struct {
		Username string
		Password string
	}{Username: user, Password: pass}
	body, _ := json.Marshal(&data)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Failed to authenticate to AM, Got %s", resp.Status)
	}
	defer resp.Body.Close()
	tokenData := make(map[string]interface{})
	if err := json.NewDecoder(resp.Body).Decode(&tokenData); err != nil {
		return err
	}
	token, ok := tokenData["token"]
	if !ok {
		return fmt.Errorf("Failed to get token")
	}
	if a.token == "" {
		a.token = token.(string)
		exp := tokenData["expires_at"].(float64)
		go a.refreshToken(int64(exp))
	}
	return nil
}

func (a *AlertManager) refreshToken(expiresAt int64) {
	// AM expectes a refresh within 30 seconds of expiry
	expiresAt = expiresAt - 20
	refresh := time.Unix(expiresAt, 0).Sub(time.Now())
	time.Sleep(refresh)
	a.Lock()
	defer a.Unlock()
	url := a.addr + "/api/auth/refresh"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.token))
	resp, err := a.Client.Do(req)
	if err != nil {
		glog.Errorf("Failed to refresh token: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		glog.Errorf("Failed to refresh token to AM, Got %s", resp.Status)
		return
	}
	tokenData := make(map[string]interface{})
	if err := json.NewDecoder(resp.Body).Decode(&tokenData); err != nil {
		return
	}
	token, ok := tokenData["token"]
	if !ok {
		glog.Errorf("Failed to get token")
		return
	}
	a.token = token.(string)
	exp := tokenData["expires_at"].(float64)
	go a.refreshToken(int64(exp))
}

func (a *AlertManager) PostAck(id int64) error {
	a.Lock()
	defer a.Unlock()
	url := a.addr + fmt.Sprintf("%s/%d/ack?owner=%s&team=%s", AlertPath, id, a.owner, a.team)
	req, _ := http.NewRequest("PATCH", url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.token))
	_, err := a.Client.Do(req)
	if err != nil {
		return fmt.Errorf("Failed to patch alert %d: %v", id, err)
	}
	return nil
}
