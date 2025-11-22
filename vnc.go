package main

import (
	"fmt"
	"net"
)

type VNCProxy struct {
	conn net.Conn
}

func NewVNCProxy(socketPath string) (*VNCProxy, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to VNC socket: %w", err)
	}
	return &VNCProxy{conn: conn}, nil
}

func (v *VNCProxy) Read(buf []byte) (int, error) {
	return v.conn.Read(buf)
}

func (v *VNCProxy) Write(buf []byte) (int, error) {
	return v.conn.Write(buf)
}

func (v *VNCProxy) Close() error {
	return v.conn.Close()
}