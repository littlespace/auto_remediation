package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const defaultTimeout = 30 * time.Second

type Command struct {
	Input   []IncidentInfo
	Name    string
	Command string
	Args    []string
	Timeout time.Duration
}

type CmdResult struct {
	RetCode int
	Error   error
	Stdout  string
	Stderr  string
}

type Executioner interface {
	Execute(ctx context.Context, cmds []Command, maxParallel int) map[string]*CmdResult
}

type Executor struct {
	cmdsPath string
}

func NewExecutor(cmdsPath string) Executioner {
	return &Executor{cmdsPath: cmdsPath}
}

func (e *Executor) Execute(ctx context.Context, cmds []Command, maxParallel int) map[string]*CmdResult {
	ret := make(map[string]*CmdResult)
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for _, cmd := range cmds {
		sem <- struct{}{}
		wg.Add(1)
		go func(cmd Command) {
			defer func() {
				wg.Done()
				<-sem
			}()
			if cmd.Timeout == 0 {
				cmd.Timeout = defaultTimeout
			}
			ctx, cancel := context.WithTimeout(ctx, cmd.Timeout)
			defer cancel()
			fullPath := filepath.Join(e.cmdsPath, cmd.Command)
			command := exec.CommandContext(ctx, fullPath, cmd.Args...)
			stdin, err := command.StdinPipe()
			if err != nil {
				ret[cmd.Name] = &CmdResult{Error: fmt.Errorf("Failed to open stdin for cmd: %s: %v", fullPath, err)}
				return
			}
			stdout, err := command.StdoutPipe()
			if err != nil {
				ret[cmd.Name] = &CmdResult{Error: fmt.Errorf("Failed to open stdout for cmd: %s: %v", fullPath, err)}
				return
			}
			stderr, err := command.StderrPipe()
			if err != nil {
				ret[cmd.Name] = &CmdResult{Error: fmt.Errorf("Failed to open stderr for cmd: %s: %v", fullPath, err)}
				return
			}
			data, err := json.Marshal(&cmd.Input)
			if err != nil {
				ret[cmd.Name] = &CmdResult{Error: fmt.Errorf("Unable to marshal stdin for cmd: %s: %v", fullPath, err)}
				return
			}
			go func() {
				defer stdin.Close()
				io.WriteString(stdin, string(data))
			}()
			if err := command.Start(); err != nil {
				ret[cmd.Name] = &CmdResult{Error: fmt.Errorf("Unable to start cmd: %s: %v", fullPath, err)}
				return
			}
			res := &CmdResult{}
			serr, _ := ioutil.ReadAll(stderr)
			sout, _ := ioutil.ReadAll(stdout)
			res.Stderr = string(serr)
			res.Stdout = string(sout)

			if err := command.Wait(); err != nil {
				if exiterr, ok := err.(*exec.ExitError); ok {
					if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
						res.RetCode = status.ExitStatus()
					}
				}
			} else {
				res.Error = err
			}
			ret[cmd.Name] = res
		}(cmd)
	}
	wg.Wait()
	return ret
}
