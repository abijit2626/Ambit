package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
)

const (
	MethodInitialize = "initialize"
	MethodToolsList  = "tools/list"
	MethodToolsCall  = "tools/call"

	NotifToolsListChanged = "notifications/tools/list_changed"
)

var ErrBatch = errors.New("mcp: JSON-RPC batch frame; forwarded but not parsed")

type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

func Parse(raw []byte) (*Message, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("mcp: empty frame")
	}
	if trimmed[0] == '[' {
		return nil, ErrBatch
	}
	if len(raw) > MaxFrameBytes {
		return nil, ErrFrameTooLarge
	}
	var m Message
	if err := json.Unmarshal(trimmed, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Message) IsResponse() bool {
	return m.Method == "" && len(m.ID) > 0 && (len(m.Result) > 0 || len(m.Error) > 0)
}

func (m *Message) IsNotification() bool {
	return m.Method != "" && len(m.ID) == 0
}

func (m *Message) IDKey() string {
	if len(m.ID) == 0 {
		return ""
	}
	return string(bytes.TrimSpace(m.ID))
}

type ServerInfo struct {
	Name            string `json:"name,omitempty"`
	Version         string `json:"version,omitempty"`
	ProtocolVersion string `json:"protocolVersion,omitempty"`
}

func ParseInitializeResult(result json.RawMessage) (ServerInfo, error) {
	var body struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(result, &body); err != nil {
		return ServerInfo{}, err
	}
	return ServerInfo{
		Name:            body.ServerInfo.Name,
		Version:         body.ServerInfo.Version,
		ProtocolVersion: body.ProtocolVersion,
	}, nil
}

type ClientInfo struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

func ParseInitializeParams(params json.RawMessage) (ClientInfo, error) {
	var body struct {
		ClientInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"clientInfo"`
	}
	if err := json.Unmarshal(params, &body); err != nil {
		return ClientInfo{}, err
	}
	return ClientInfo{Name: body.ClientInfo.Name, Version: body.ClientInfo.Version}, nil
}
