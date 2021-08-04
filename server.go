// license that can be found in the LICENSE file.

// package udpsocket is a simple UDP server to make a virtual secure channel with the clients
package udpsocket

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/theredrad/udpsocket/crypto"
	"github.com/theredrad/udpsocket/encoding"
	"github.com/theredrad/udpsocket/encoding/pb"
	"net"
	"time"
)

// HandlerFunc is called when a custom message type is received from the client
type HandlerFunc func(id string, t byte, p []byte)

// custom error types
var (
	ErrInvalidRecordType            = errors.New("invalid record type")
	ErrInsecureEncryptionKeySize    = errors.New("insecure encryption key size")
	ErrClientSessionNotFound        = errors.New("client session not found")
	ErrClientAddressIsNotRegistered = errors.New("client address is not registered")
	ErrClientNotFound               = errors.New("client not found")
	ErrMinimumPayloadSizeLimit      = errors.New("minimum payload size limit")
	ErrClientCookieIsInvalid        = errors.New("client cookie is invalid")
	ErrInvalidPayloadBodySize       = errors.New("payload body size is invalid")
)

const (
	// reserved record types
	HandshakeClientHelloRecordType byte = 1
	HandshakeHelloVerifyRecordType byte = 2
	HandshakeServerHelloRecordType byte = 3
	PingRecordType                 byte = 4
	PongRecordType                 byte = 5

	// default RSA key size, this config is used to initiate new RSA implementation if no asymmetric encryption is passed
	defaultRSAKeySize int = 2048

	// A symmetric key smaller than 256 bits is not secure. 256-bits = 32 bytes in size
	insecureSymmKeySize int = 32
)

// incoming bytes is parsed to the record struct
type record struct {
	Type       byte
	ProtoMajor uint8
	ProtoMinor uint8
	Body       []byte
	Extra      []byte
}

// client is an authenticated UDP client
type Client struct {
	ID string

	// Session ID is a secret byte array that indicates the client is already done the handshake process, the client must prepend these bytes into the start of each record body before encryption
	sessionID []byte

	// UDP address of the client
	addr *net.UDPAddr

	// Client encryption key to decrypt & encrypt a record body with the symmetric encryption algorithm
	eKey []byte //encryption key

	// Last time that a record is received from the client
	lastHeartbeat *time.Time
}

// Server config
type Config struct {
	// an implementation of the AuthClient to authenticate the user token, if not set, no authentication will apply
	AuthClient AuthClient

	// an implementation of the Transcoder to encode & decode the record body, if not set, an implementation of the Protobuf will use
	Transcoder encoding.Transcoder

	// an implementation of Symmetric encryption to encrypt & decrypt records body for the client after a successful handshake
	SymmCrypto crypto.Symmetric

	// an implementation of Asymmetric encryption to decrypt the body of the client handshake hello record
	AsymmCrypto crypto.Asymmetric

	// the Session manager generates cookie & session ID
	sessionManager *sessionManager

	// Buffer limit size for incoming bytes
	ReadBufferSize int

	// Minimum payload size to ignore too short incoming bytes
	MinimumPayloadSize int

	// Protocol major version
	ProtocolVersionMajor uint8

	// Protocol minor version
	ProtocolVersionMinor uint8

	protocolVersion [2]byte
}

// The Server is a UDP listener that handles the handshake process, encryption, client authentication, sending records to the client & proxy custom record types to the handler method
type Server struct {
	// UDP connection to listen
	conn *net.UDPConn

	// Server config which contains AuthClient, Transcoder, Cryptography ...
	config *Config

	// Handler func which is called when a custom record type received
	handler HandlerFunc

	// Map of client with index of client ID
	clients map[string]*Client

	// Map of client with index of IP_PORT
	sessions map[string]*Client

	// Channel of server errors
	Errors chan error
}

// NewServer accepts UDP connection & configs & returns a new instance of the Server
// If config is nil or any required config isn't passed, a default instance of it will be set, e.g. Protobuf implementation if no Transcoder is set
func NewServer(conn *net.UDPConn, config *Config) (*Server, error) {
	if config == nil {
		config = &Config{}
	}

	config.protocolVersion = [2]byte{config.ProtocolVersionMajor, config.ProtocolVersionMinor}

	if config.SymmCrypto == nil {
		config.SymmCrypto = crypto.NewAES(crypto.AES_CBC)
	}

	var err error
	if config.AsymmCrypto == nil {
		config.AsymmCrypto, err = crypto.NewRSA(defaultRSAKeySize)
		if err != nil {
			return nil, err
		}
	}

	if config.AuthClient == nil {
		config.AuthClient = &DefaultAuthClient{}
	}

	if config.Transcoder == nil {
		config.Transcoder = &pb.Protobuf{}
	}

	config.sessionManager, err = newSessionManager()
	if err != nil {
		return nil, err
	}

	return &Server{
		conn:   conn,
		config: config,

		clients:  make(map[string]*Client),
		sessions: make(map[string]*Client),

		Errors: make(chan error),
	}, nil
}

// Set handler function as a callback to call when a custom record type is received from the client
func (s *Server) SetHandler(f HandlerFunc) {
	s.handler = f
}

// Start listening to the UDP port for incoming bytes & then pass it to the handleRecord method if no error is found
func (s *Server) Serve() chan error {
	buf := make([]byte, s.config.ReadBufferSize)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			s.Errors <- err
			continue
		}
		go s.handleRecord(buf[0:n], addr)
	}
}

// handlerRecord validate & parse incoming bytes to a record instance, then process it depends on the record type
// all incoming bytes will ignore if hasn't minimum payload size (to prevent process empty or wrong formatted records)
// HandshakeClientHello record is encrypted by the server public key & contains the client encryption key
// if the ClientHello was valid, the server generates a unique cookie for the client address, encrypt it with the client key & then send it
// client must send the HandshakeClientHelloVerify request (same as Hello) with the generated cookie & the token to prove that the sender address is valid
// server validate the HelloVerify record, then authenticate the client token & if they're valid, generate a session ID, encrypt it & send it back as ServerHello record
// after client registration, the client must prepend the Session ID before the record body unencrypted bytes, then encrypt them & compose the record
// all custom record types will validate & authenticate, then pass to the handler method with the client ID
// if a ping record is received, the server sends a pong record immediately
func (s *Server) handleRecord(record []byte, addr *net.UDPAddr) {
	if len(record) < s.config.MinimumPayloadSize {
		s.Errors <- ErrMinimumPayloadSizeLimit
		return
	}

	r, err := parseRecord(record)
	if err != nil {
		s.Errors <- err
		return
	}

	switch r.Type {
	case HandshakeClientHelloRecordType:
		var payload []byte
		payload, err = s.config.AsymmCrypto.Decrypt(r.Body)
		if err != nil {
			s.Errors <- err
			return
		}

		var handshake encoding.HandshakeRecord
		handshake, err = s.config.Transcoder.UnmarshalHandshake(payload)
		if err != nil {
			s.Errors <- fmt.Errorf("error while unmarshaling ClientHello record: %w", err)
			return
		}

		//TODO validate the client random

		if len(handshake.GetCookie()) == 0 {
			cookie := s.config.sessionManager.GetAddrCookieHMAC(addr, []byte(handshake.GetClientVersion()), handshake.GetSessionId(), handshake.GetRandom()) //TODO session id is empty

			if len(handshake.GetKey()) < insecureSymmKeySize {
				s.Errors <- fmt.Errorf("error while parsing ClientHello record: %w", ErrInsecureEncryptionKeySize)
				return
			}

			serverHandshakeVerify := s.config.Transcoder.NewHandshakeRecord()
			serverHandshakeVerify.SetCookie(cookie)
			serverHandshakeVerify.SetTimestamp(time.Now().UnixNano() / int64(time.Millisecond))

			var handshakePayload []byte
			handshakePayload, err = s.config.Transcoder.MarshalHandshake(serverHandshakeVerify)
			if err != nil {
				s.Errors <- fmt.Errorf("error while creating HelloVerify record: %w", err)
				return
			}

			handshakePayload, err = s.config.SymmCrypto.Encrypt(handshakePayload, handshake.GetKey())
			if err != nil {
				s.Errors <- fmt.Errorf("error while encrypting HelloVerify record: %w", err)
				return
			}

			handshakePayload = composeRecordBytes(HandshakeHelloVerifyRecordType, s.config.protocolVersion, handshakePayload)

			err = s.sendToAddr(addr, handshakePayload)
			if err != nil {
				s.Errors <- fmt.Errorf("error while sending HelloVerify record to the client: %w", err)
				return
			}
		} else {
			cookie := s.config.sessionManager.GetAddrCookieHMAC(addr, []byte(handshake.GetClientVersion()), handshake.GetSessionId(), handshake.GetRandom()) //TODO session id is empty
			if !crypto.HMACEqual(handshake.GetCookie(), cookie) {
				s.Errors <- fmt.Errorf("error while validation HelloVerify record cookie: %w", ErrClientCookieIsInvalid)
				return
			}

			if len(handshake.GetKey()) < insecureSymmKeySize {
				s.Errors <- fmt.Errorf("error while validating HelloVerify record key: %w", ErrInsecureEncryptionKeySize)
				return
			}

			var token []byte
			if len(r.Extra) > 0 {
				token, err = s.config.SymmCrypto.Decrypt(r.Extra, handshake.GetKey())
				if err != nil {
					s.Errors <- fmt.Errorf("error while decrypting HelloVerify record token: %w", err)
					return
				}
			}

			var ID string
			ID, err = s.config.AuthClient.Authenticate(context.Background(), token)
			if err != nil {
				s.Errors <- fmt.Errorf("error while authenticating client token: %w", err)
				return
			}

			var cl *Client
			cl, err = s.registerClient(addr, ID, handshake.GetKey())
			if err != nil {
				s.Errors <- fmt.Errorf("error while registering client: %w", err)
				return
			}

			serverHandshakeHello := s.config.Transcoder.NewHandshakeRecord()
			serverHandshakeHello.SetSessionId(cl.sessionID)
			serverHandshakeHello.SetTimestamp(time.Now().UnixNano() / int64(time.Millisecond))

			var handshakePayload []byte
			handshakePayload, err = s.config.Transcoder.MarshalHandshake(serverHandshakeHello)
			if err != nil {
				s.Errors <- fmt.Errorf("error while marshaling server hello record: %w", err)
				return
			}

			err = s.sendToClient(cl, HandshakeServerHelloRecordType, handshakePayload)
			if err != nil {
				s.Errors <- fmt.Errorf("error while sending server hello record: %w", err)
				return
			}
		}
	case PingRecordType:
		cl, ok := s.findClientByAddr(addr)
		if !ok {
			s.Errors <- fmt.Errorf("error while authenticating ping record: %w", ErrClientAddressIsNotRegistered)
			return
		}

		pong := s.config.Transcoder.NewPongRecord()
		pong.SetReceivedAt(time.Now().UnixNano())

		var payload []byte
		payload, err = s.config.SymmCrypto.Decrypt(r.Body, cl.eKey)
		if err != nil {
			s.Errors <- fmt.Errorf("error while decrypting ping record: %w", err)
			return
		}

		var sessionID, body []byte
		sessionID, body, err = parseSessionID(payload, len(cl.sessionID))
		if err != nil {
			s.Errors <- fmt.Errorf("error while parsing session id for ping: %w", err)
			return
		}

		if !cl.ValidateSessionID(sessionID) {
			s.Errors <- fmt.Errorf("error while validating session id for ping: %w", ErrClientSessionNotFound)
			return
		}

		var ping encoding.PingRecord
		ping, err = s.config.Transcoder.UnmarshalPing(body)
		if err != nil {
			s.Errors <- fmt.Errorf("error while unmarshaling ping record: %w", err)
			return
		}

		pong.SetPingSentAt(ping.GetSentAt())
		pong.SetSentAt(time.Now().UnixNano())

		var pongPayload []byte
		pongPayload, err = s.config.Transcoder.MarshalPong(pong)
		if err != nil {
			s.Errors <- fmt.Errorf("error while marshaling pong record: %w", err)
			return
		}

		err = s.sendToClient(cl, PongRecordType, pongPayload)
		if err != nil {
			s.Errors <- fmt.Errorf("error while sending pong record: %w", err)
			return
		}

	default:
		cl, ok := s.findClientByAddr(addr)
		if !ok {
			s.Errors <- fmt.Errorf("error while authenticating other type record: %w", ErrClientAddressIsNotRegistered)
			return
		}

		var payload []byte
		payload, err = s.config.SymmCrypto.Decrypt(r.Body, cl.eKey)
		if err != nil {
			s.Errors <- fmt.Errorf("error while decrypting other type record: %w", err)
			return
		}

		var sessionID, body []byte
		sessionID, body, err = parseSessionID(payload, len(cl.sessionID))
		if err != nil {
			s.Errors <- fmt.Errorf("error while parsing session id for ping: %w", err)
			return
		}

		if !cl.ValidateSessionID(sessionID) {
			s.Errors <- fmt.Errorf("error while validating client session for other type record: %w", ErrClientSessionNotFound)
			return
		}

		if s.handler != nil {
			s.handler(cl.ID, r.Type, body)
		}
	}
}

// parseSessionID parses the session ID from the record decrypted body, the session ID must prepend to the body before encryption in the client
func parseSessionID(p []byte, sLen int) ([]byte, []byte, error) {
	if len(p) < sLen {
		return nil, nil, ErrInvalidPayloadBodySize
	}
	return p[:sLen], p[sLen:], nil
}

// registerClient generates a new session ID & registers an address with token ID & encryption key as a Client
func (s *Server) registerClient(addr *net.UDPAddr, ID string, eKey []byte) (*Client, error) {
	sessionID, err := s.config.sessionManager.GenerateSessionID(addr, ID)
	if err != nil {
		return nil, err
	}

	cl := &Client{
		ID:        ID,
		sessionID: sessionID,
		addr:      addr,
		eKey:      eKey,
	}
	s.clients[ID] = cl
	s.sessions[fmt.Sprintf("%s_%d", addr.IP.String(), addr.Port)] = cl

	return cl, nil
}

// returns the Client by the Session ID
func (s *Server) findClientBySessionID(sessionID []byte) (*Client, bool) {
	for _, client := range s.clients {
		if bytes.Equal(client.sessionID, sessionID) {
			return client, true
		}
	}
	return nil, false
}

// returns the Client ID by the session ID
func (s *Server) findClientIDBySessionID(sessionID []byte) (string, bool) {
	cl, ok := s.findClientBySessionID(sessionID)
	if !ok {
		return "", ok
	}

	return cl.ID, true
}

// returns the Client by IP & Port
func (s *Server) findClientByAddr(addr *net.UDPAddr) (*Client, bool) {
	cl, ok := s.sessions[fmt.Sprintf("%s_%d", addr.IP.String(), addr.Port)]
	if !ok {
		return nil, ok
	}

	return cl, true
}

// sends a record bytes to the UDP address
func (s *Server) sendToAddr(addr *net.UDPAddr, record []byte) error {
	_, err := s.conn.WriteToUDP(record, addr)
	return err
}

// sends a record byte array to the Client. the record type is prepended to the record body as a byte
func (s *Server) sendToClient(client *Client, typ byte, payload []byte) error {
	payload, err := s.config.SymmCrypto.Encrypt(payload, client.eKey)
	if err != nil {
		return err
	}
	payload = composeRecordBytes(typ, s.config.protocolVersion, payload)
	return s.sendToAddr(client.addr, payload)
}

// a method to send byte array to the Client by ID
func (s *Server) SendToClientByID(clientID string, typ byte, payload []byte) error {
	cl, ok := s.clients[clientID]
	if !ok {
		return ErrClientNotFound
	}

	return s.sendToClient(cl, typ, payload)
}

// a method to broadcast byte array to all registered Clients
func (s *Server) BroadcastToClients(typ byte, payload []byte) {
	for _, cl := range s.clients {
		client := cl
		go func() {
			err := s.sendToClient(client, typ, payload)
			if err != nil {
				s.Errors <- err
			}
		}()
	}
}

// composes record bytes, prepend the record header (type & protocol version) to the body
func composeRecordBytes(typ byte, version [2]byte, payload []byte) []byte {
	return append([]byte{typ, version[0], version[1]}, payload...)
}

// parses received bytes to the record struct
func parseRecord(rec []byte) (*record, error) {
	if rec[0] != HandshakeClientHelloRecordType {
		if len(rec) < 3 {
			return nil, ErrInvalidRecordType
		}

		return &record{
			Type:       rec[0],
			ProtoMajor: rec[1],
			ProtoMinor: rec[2],
			Body:       rec[3:],
		}, nil
	}

	if len(rec) < 5 {
		return nil, ErrInvalidRecordType
	}

	bodySize := 256*int(rec[3]) + int(rec[4])

	return &record{
		Type:       rec[0],
		ProtoMajor: rec[1],
		ProtoMinor: rec[2],
		Body:       rec[5 : bodySize+5],
		Extra:      rec[bodySize+5:],
	}, nil
}

// compares the client session ID with the given one
func (c *Client) ValidateSessionID(sessionID []byte) bool {
	if bytes.Equal(c.sessionID, sessionID) {
		return true
	}
	return false
}
