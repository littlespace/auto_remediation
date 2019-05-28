package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func execute() {
	i := Incident{}
	if err := json.NewDecoder(os.Stdin).Decode(&i); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading standard input: %v", err)
		os.Exit(1)
	}
	if i.Name == "pass" {
		fmt.Fprint(os.Stderr, "Successfully executed")
		fmt.Fprint(os.Stdout, `{"result": "pass", "message": "good"}`)
		os.Exit(0)
	} else {
		fmt.Fprint(os.Stderr, "Failed to execute")
		fmt.Fprint(os.Stdout, `{"result": "fail", "message": "dumped"}`)
		os.Exit(1)
	}
}

func TestExecution(t *testing.T) {
	runnerCmd = os.Args[0]
	exe := &Executor{}
	cmd := Command{
		Input: &Incident{Name: "pass"},
		Name:  "Test passing",
		Env:   []string{"testme=1"},
	}
	result := exe.Execute(context.Background(), []Command{cmd}, 1)
	for _, res := range result {
		assert.Nil(t, res.Error)
		assert.Equal(t, res.RetCode, 0)
		assert.Equal(t, res.Stderr, "Successfully executed")
		assert.Equal(t, res.Stdout, `{"result": "pass", "message": "good"}`)
	}
	cmd = Command{
		Input: &Incident{Name: "fail"},
		Name:  "Test failing",
		Env:   []string{"testme=1"},
	}
	result = exe.Execute(context.Background(), []Command{cmd}, 1)
	for _, res := range result {
		assert.Nil(t, res.Error)
		assert.Equal(t, res.RetCode, 1)
		assert.Equal(t, res.Stderr, "Failed to execute")
		assert.Equal(t, res.Stdout, `{"result": "fail", "message": "dumped"}`)
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("testme") == "1" {
		execute()
		return
	}
	os.Exit(m.Run())
}
