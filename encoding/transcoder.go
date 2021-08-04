package encoding

type HandshakeRecord interface {
	GetClientVersion() string
	GetCipherSuites() []byte
	SetCipherSuites([]byte)
	GetSessionId() []byte
	SetSessionId([]byte)
	GetRandom() []byte
	GetCookie() []byte
	SetCookie([]byte)
	GetToken() []byte
	GetKey() []byte
	GetTimestamp() int64
	SetTimestamp(int64)
}

type PingRecord interface {
	GetSentAt() int64
}

type PongRecord interface {
	GetPingSentAt() int64
	SetPingSentAt(int64)
	GetReceivedAt() int64
	SetReceivedAt(int64)
	GetSentAt() int64
	SetSentAt(int64)
}

type Transcoder interface {
	Marshal(interface{}) ([]byte, error)
	Unmarshal([]byte, interface{}) error

	NewHandshakeRecord() HandshakeRecord
	MarshalHandshake(HandshakeRecord) ([]byte, error)
	UnmarshalHandshake([]byte) (HandshakeRecord, error)

	UnmarshalPing([]byte) (PingRecord, error)
	NewPongRecord() PongRecord
	MarshalPong(PongRecord) ([]byte, error)
}
