package pb

import (
	"errors"
	"github.com/golang/protobuf/proto"
	"github.com/theredrad/udpsocket/encoding"
)

var (
	errInvalidProtobufMessage = errors.New("invalid protobuf message")
)

type Protobuf struct{}

func (p *Protobuf) Marshal(msg interface{}) ([]byte, error) {
	m, ok := msg.(proto.Message)
	if !ok {
		return nil, errInvalidProtobufMessage
	}
	return proto.Marshal(m)
}

func (p *Protobuf) Unmarshal(raw []byte, msg interface{}) error {
	m, ok := msg.(proto.Message)
	if !ok {
		return errInvalidProtobufMessage
	}
	return proto.Unmarshal(raw, m)
}

func (p *Protobuf) NewHandshakeRecord() encoding.HandshakeRecord {
	return &Handshake{}
}

func (p *Protobuf) MarshalHandshake(h encoding.HandshakeRecord) ([]byte, error) {
	msg := &Handshake{
		ClientVersion: h.GetClientVersion(),
		SessionId:     h.GetSessionId(),
		Random:        h.GetRandom(),
		Cookie:        h.GetCookie(),
		Token:         h.GetToken(),
		Key:           h.GetKey(),
		Timestamp:     h.GetTimestamp(),
	}
	return proto.Marshal(msg)
}

func (p *Protobuf) UnmarshalHandshake(b []byte) (encoding.HandshakeRecord, error) {
	h := &Handshake{}
	err := proto.Unmarshal(b, h)
	return h, err
}

func (p *Protobuf) NewPongRecord() encoding.PongRecord {
	return &Pong{}
}

func (p *Protobuf) UnmarshalPing(b []byte) (encoding.PingRecord, error) {
	pi := &Ping{}
	err := proto.Unmarshal(b, pi)
	return pi, err
}

func (p *Protobuf) MarshalPong(pr encoding.PongRecord) ([]byte, error) {
	msg := &Pong{
		PingSentAt: pr.GetPingSentAt(),
		ReceivedAt: pr.GetReceivedAt(),
		SentAt:     pr.GetSentAt(),
	}
	return proto.Marshal(msg)
}
