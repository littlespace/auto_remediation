package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/golang/glog"
	"github.com/mayuresh82/auto_remediation/models"
)

type Notifier interface {
	Send(rem *models.Remediation, msg string) error
}

type SlackNotifier struct {
	Url     string
	Channel string
	Mention string
}

func (n *SlackNotifier) Send(rem *models.Remediation, msg string) error {
	message := n.Mention + " " + msg
	fields := []map[string]interface{}{
		map[string]interface{}{
			"title": "RemediationID", "value": rem.Id, "short": false,
		},
		map[string]interface{}{
			"title": "IncidentID", "value": rem.IncidentId, "short": false,
		},
		map[string]interface{}{
			"title": "IncidentName", "value": rem.IncidentName, "short": false,
		},
	}

	title := fmt.Sprintf("Auto Remediator")
	body := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"title":  title,
				"text":   message,
				"fields": fields,
				"footer": "via Auto Remediator",
				"ts":     rem.StartTime.Unix(),
			},
		},
		"parse": "full", // to linkify urls, users and channels in alert message.
	}
	if n.Channel != "" {
		body["channel"] = n.Channel
	}
	data, err := json.Marshal(&body)
	if err != nil {
		return err
	}
	c := &http.Client{
		Timeout: 2 * time.Second,
	}
	resp, err := c.Post(n.Url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		glog.Errorf("Output: Unable to post to slack: %v", err)
		return err
	}
	if resp.StatusCode != http.StatusOK {
		//n.statsPostError.Add(1)
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			body = []byte{}
		}
		glog.Errorf("Output: Unable to post to slack: Got HTTP %d: %v", resp.StatusCode, string(body))
	}
	return nil
}
