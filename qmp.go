package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"sync"
)

type QMPClient struct {
	conn   net.Conn
	reader *bufio.Reader
	mu     sync.Mutex
}

type QMPCommand struct {
	Execute   string                 `json:"execute"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

type QMPResponse struct {
	Return json.RawMessage        `json:"return,omitempty"`
	Error  *QMPError              `json:"error,omitempty"`
	Event  string                 `json:"event,omitempty"`
	Data   map[string]interface{} `json:"data,omitempty"`
}

type QMPError struct {
	Class string `json:"class"`
	Desc  string `json:"desc"`
}

func NewQMPClient(socketPath string) (*QMPClient, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to QMP socket: %w", err)
	}
	client := &QMPClient{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}
	if _, err := client.reader.ReadBytes('\n'); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read QMP greeting: %w", err)
	}
	if err := client.Execute("qmp_capabilities", nil); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to negotiate QMP: %w", err)
	}
	return client, nil
}

func (c *QMPClient) Execute(command string, args map[string]interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cmd := QMPCommand{
		Execute:   command,
		Arguments: args,
	}
	data, err := json.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("failed to marshal command: %w", err)
	}
	if _, err := c.conn.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to send command: %w", err)
	}
	for {
		line, err := c.reader.ReadBytes('\n')
		if err != nil {
			return fmt.Errorf("failed to read response: %w", err)
		}
		var resp QMPResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			continue
		}
		if resp.Event != "" {
			continue
		}
		if resp.Error != nil {
			return fmt.Errorf("QMP error: %s - %s", resp.Error.Class, resp.Error.Desc)
		}
		return nil
	}
}

func (c *QMPClient) Close() error {
	return c.conn.Close()
}