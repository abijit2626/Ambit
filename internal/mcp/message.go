package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Method names and notifications this package recognizes. Everything else is
// forwarded and ignored: the interposer has no opinion on methods it does not
// need, and enumerating them would be a maintenance burden that buys nothing.
const (
	MethodInitialize = "initialize"
	MethodToolsList  = "tools/list"
	MethodToolsCall  = "tools/call"

	// NotifToolsListChanged is a rug pull's most convenient arrival path: the
	// server tells the client its tool surface changed mid-session, the client
	// re-lists, and a description that was reviewed at startup is replaced by one
	// that never was. The interposer records the notification itself and tags the
	// listing that follows, so D4 sees both halves.
	NotifToolsListChanged = "notifications/tools/list_changed"
)

// ErrBatch reports a JSON-RPC batch frame. Batching was removed in MCP
// 2025-06-18 but older servers may still send it. We forward it and decline to
// parse rather than half-understanding it; the counter this produces is how we
// would learn it matters in practice.
var ErrBatch = errors.New("mcp: JSON-RPC batch frame; forwarded but not parsed")

// Message is the JSON-RPC envelope, kept deliberately shallow.
//
// Params and Result stay as RawMessage: this package never re-serializes a
// message back into the stream, so there is no need to model bodies it does not
// read, and holding raw bytes means an unknown field cannot be silently dropped
// by a round trip that never happens.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// Parse decodes a frame's envelope.
//
// Callers must treat an error as "forward anyway": every caller in this codebase
// has already forwarded the bytes before calling Parse.
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

// IsResponse reports whether the message carries a result or an error for a
// request, rather than being a request or notification itself.
func (m *Message) IsResponse() bool {
	return m.Method == "" && len(m.ID) > 0 && (len(m.Result) > 0 || len(m.Error) > 0)
}

// IsNotification reports whether the message is a notification: a method call
// with no id, which by protocol expects no reply.
func (m *Message) IsNotification() bool {
	return m.Method != "" && len(m.ID) == 0
}

// IDKey returns a comparable key for the request id.
//
// JSON-RPC ids may be strings or numbers, and a client is free to use either, so
// the raw JSON form is the key. Whitespace is trimmed because a client is also
// free to send `"id" : 1`.
func (m *Message) IDKey() string {
	if len(m.ID) == 0 {
		return ""
	}
	return string(bytes.TrimSpace(m.ID))
}

// ServerInfo is the subset of an initialize result worth recording: the server's
// own claim about what it is.
//
// It is a claim, not evidence — a compromised server can say anything — so it is
// kept in the local spool for investigation and never used to classify trust.
// Trust comes from operator configuration only; see docs/02 on annotations being
// one-directional.
type ServerInfo struct {
	Name            string `json:"name,omitempty"`
	Version         string `json:"version,omitempty"`
	ProtocolVersion string `json:"protocolVersion,omitempty"`
}

// ParseInitializeResult extracts server info from an initialize result.
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

// ClientInfo is the client's self-description from an initialize request. Like
// ServerInfo it is a claim, recorded for correlation rather than trusted.
type ClientInfo struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// ParseInitializeParams extracts client info from an initialize request.
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
