package remediator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/golang/glog"
	"net/http"
	"time"
)

const (
	alertPath = "/api/alerts"
	owner     = "auto_remediator"
	team      = "neteng"
)

func getStatus(addr string, id int64) (string, error) {
	url := addr + fmt.Sprintf("%s/%d", alertPath, id)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("Failed to query alert %d: %v", id, err)
	}
	defer resp.Body.Close()
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", fmt.Errorf("Unable to decode json body: %v", err)
	}
	return data["Status"].(string), nil
}

func assertStatus(desiredStatus, addr string, id int64, checkInterval time.Duration, checkCount int) bool {
	for i := 0; i < checkCount; i++ {
		status, err := getStatus(addr, id)
		if err != nil {
			glog.Errorf("Failed to check alert %s status: %v", id, err)
			return false
		}
		if status != desiredStatus {
			return false
		}
		time.Sleep(checkInterval)
	}
	return true
}

func waitOnStatus(desiredStatus, addr string, id int64, checkInterval time.Duration, checkCount int) bool {
	for i := 0; i < checkCount; i++ {
		status, err := getStatus(addr, id)
		if err != nil {
			glog.Errorf("Failed to check alert %s status: %v", id, err)
			return false
		}
		if status == desiredStatus {
			return true
		}
		time.Sleep(checkInterval)
	}
	return false
}

func postAck(addr string, id int64, user, pass string) error {
	url := addr + "/api/auth"
	data := struct {
		Username string
		Password string
	}{Username: user, Password: pass}
	body, _ := json.Marshal(&data)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	tokenData := make(map[string]string)
	if err := json.NewDecoder(resp.Body).Decode(&tokenData); err != nil {
		return err
	}
	token, ok := tokenData["token"]
	if !ok {
		return fmt.Errorf("Failed to get token")
	}

	url = addr + fmt.Sprintf("%s/%d/ack?owner=%s&team=%s", alertPath, id, owner, team)
	req, _ = http.NewRequest("PATCH", url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	_, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("Failed to post alert %d: %v", id, err)
	}
	return nil
}
