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
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"
)

// HandlerFunc is called when a custom message type is received from the client
type HandlerFunc func(id string, t byte, p []byte)

type Option func(*Server)

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
	HandshakeClientHelloRecordType byte = iota + 1
	HandshakeHelloVerifyRecordType
	HandshakeServerHelloRecordType
	PingRecordType
	PongRecordType
	UnAuthenticated

	// default RSA key size, this options is used to initiate new RSA implementation if no asymmetric encryption is passed
	defaultRSAKeySize         int = 2048
	defaultMinimumPayloadSize int = 3
	defaultReadBufferSize     int = 2048

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

type rawRecord struct {
	payload []byte
	addr    *net.UDPAddr
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

	sync.Mutex
}

// The Server is a UDP listener that handles the handshake process, encryption, client authentication, sending records to the client & proxy custom record types to the handler method
type Server struct {
	// UDP connection to listen
	conn *net.UDPConn

	// an implementation of the AuthClient to authenticate the user token, if not set, no authentication will apply
	authClient AuthClient

	// an implementation of the Transcoder to encode & decode the record body, if not set, an implementation of the Protobuf will use
	transcoder encoding.Transcoder

	// an implementation of Asymmetric encryption to decrypt the body of the client handshake hello record
	asymmCrypto crypto.Asymmetric

	// an implementation of Symmetric encryption to encrypt & decrypt records body for the client after a successful handshake
	symmCrypto crypto.Symmetric

	// Buffer limit size for incoming bytes
	readBufferSize int

	// Minimum payload size to ignore too short incoming bytes
	minimumPayloadSize int

	// Expiration time of last heartbeat to delete client
	heartbeatExpiration time.Duration

	// Handler func which is called when a custom record type received
	handler HandlerFunc

	// Map of client with index of client ID
	clients map[string]*Client

	// Client garbage collector ticker
	garbageCollectionTicker *time.Ticker

	// Client garbage collector stop channel
	garbageCollectionStop chan bool

	// the Session manager generates cookie & session ID
	sessionManager *sessionManager

	// Map of client with index of IP_PORT
	sessions map[string]*Client

	// stop channel to stop listening
	stop chan bool

	// Protocol version
	protocolVersion [2]byte

	rawRecords chan rawRecord

	// Logger
	logger *log.Logger

	wg *sync.WaitGroup
}

// NewServer accepts UDP connection & configs & returns a new instance of the Server
// If options is nil or any required options isn't passed, a default instance of it will be set, e.g. Protobuf implementation if no Transcoder is set
func NewServer(conn *net.UDPConn, options ...Option) (*Server, error) {
	s := Server{
		conn: conn,

		clients:  make(map[string]*Client),
		sessions: make(map[string]*Client),

		garbageCollectionStop: make(chan bool, 1),
		stop:                  make(chan bool, 1),

		wg: &sync.WaitGroup{},

		rawRecords: make(chan rawRecord),
	}

	for _, opt := range options {
		opt(&s)
	}

	if s.readBufferSize == 0 {
		s.readBufferSize = defaultReadBufferSize
	}

	if s.minimumPayloadSize == 0 {
		s.minimumPayloadSize = defaultMinimumPayloadSize
	}

	if s.symmCrypto == nil {
		s.symmCrypto = crypto.NewAES(crypto.AES_CBC)
	}

	var err error
	if s.asymmCrypto == nil {
		s.asymmCrypto, err = crypto.NewRSA(defaultRSAKeySize)
		if err != nil {
			return nil, err
		}
	}

	if s.authClient == nil {
		s.authClient = &DefaultAuthClient{}
	}

	if s.transcoder == nil {
		s.transcoder = &pb.Protobuf{}
	}

	s.sessionManager, err = newSessionManager()
	if err != nil {
		return nil, err
	}

	if s.logger == nil { // discard logging if no logger is set
		s.logger = log.New(ioutil.Discard, "", 0)
	}

	return &s, nil
}

// Set handler function as a callback to call when a custom record type is received from the client
func (s *Server) SetHandler(f HandlerFunc) {
	s.handler = f
}

func (s *Server) handleRawRecords() {
	for {
		select {
		case r := <-s.rawRecords:
			s.handleRecord(r.payload, r.addr)
		}
	}
}

// Start listening to the UDP port for incoming bytes & then pass it to the handleRecord method if no error is found
func (s *Server) Serve() {
	if s.heartbeatExpiration > 0 {
		if s.garbageCollectionTicker != nil {
			s.garbageCollectionTicker.Stop()
		}
		s.garbageCollectionTicker = time.NewTicker(s.heartbeatExpiration)
		s.garbageCollectionStop = make(chan bool, 1)
		go s.clientGarbageCollection()
	}

	go s.handleRawRecords()

	s.conn.SetReadDeadline(time.Time{}) // reset read deadline @TODO: handle error
	s.stop = make(chan bool, 1)         // reset the stop channel
	for {
		select {
		case _ = <-s.stop:
			return
		default:
			buf := make([]byte, s.readBufferSize)
			n, addr, err := s.conn.ReadFromUDP(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					continue
				}

				s.logger.Printf("error while reading from udp: %s", err)
				continue
			}
			s.rawRecords <- rawRecord{
				payload: buf[0:n],
				addr:    addr,
			}
			//go s.handleRecord(buf[0:n], addr)
		}
	}
}

func (s *Server) Stop() {
	s.conn.SetReadDeadline(time.Unix(0, 1)) // set read deadline to a longtime ago @TODO: handle error
	s.stop <- true
	s.garbageCollectionStop <- true
	s.wg.Wait()
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
	if len(record) < s.minimumPayloadSize {
		s.logger.Println(ErrMinimumPayloadSizeLimit)
		return
	}

	r, err := parseRecord(record)
	if err != nil {
		s.logger.Printf("error while parsing record: %s", err)
		return
	}

	switch r.Type {
	case HandshakeClientHelloRecordType:
		s.handleHandshakeRecord(context.Background(), addr, r)
	case PingRecordType:
		s.handlePingRecord(context.Background(), addr, r)
	default:
		s.handleCustomRecord(context.Background(), addr, r)
	}
}

// handleHandshakeRecord handles handshake process
func (s *Server) handleHandshakeRecord(ctx context.Context, addr *net.UDPAddr, r *record) {
	var payload []byte
	payload, err := s.asymmCrypto.Decrypt(r.Body)
	if err != nil {
		s.logger.Printf("error while decrypting record body: %s", err)
		return
	}

	var handshake encoding.HandshakeRecord
	handshake, err = s.transcoder.UnmarshalHandshake(payload)
	if err != nil {
		s.logger.Printf("error while unmarshaling ClientHello record: %s", err)
		return
	}

	//TODO validate the client random

	if len(handshake.GetCookie()) == 0 {
		cookie := s.sessionManager.GetAddrCookieHMAC(addr, []byte(handshake.GetClientVersion()), handshake.GetSessionId(), handshake.GetRandom()) //TODO session id is empty

		if len(handshake.GetKey()) < insecureSymmKeySize {
			s.logger.Printf("error while parsing ClientHello record: %s", ErrInsecureEncryptionKeySize)
			return
		}

		serverHandshakeVerify := s.transcoder.NewHandshakeRecord()
		serverHandshakeVerify.SetCookie(cookie)
		serverHandshakeVerify.SetTimestamp(time.Now().UnixNano() / int64(time.Millisecond))

		var handshakePayload []byte
		handshakePayload, err = s.transcoder.MarshalHandshake(serverHandshakeVerify)
		if err != nil {
			s.logger.Printf("error while creating HelloVerify record: %s", err)
			return
		}

		handshakePayload, err = s.symmCrypto.Encrypt(handshakePayload, handshake.GetKey())
		if err != nil {
			s.logger.Printf("error while encrypting HelloVerify record: %s", err)
			return
		}

		handshakePayload = composeRecordBytes(HandshakeHelloVerifyRecordType, s.protocolVersion, handshakePayload)

		err = s.sendToAddr(addr, handshakePayload)
		if err != nil {
			s.logger.Printf("error while sending HelloVerify record to the client: %s", err)
			return
		}
	} else {
		cookie := s.sessionManager.GetAddrCookieHMAC(addr, []byte(handshake.GetClientVersion()), handshake.GetSessionId(), handshake.GetRandom()) //TODO session id is empty
		if !crypto.HMACEqual(handshake.GetCookie(), cookie) {
			s.logger.Printf("error while validation HelloVerify record cookie: %s", ErrClientCookieIsInvalid)
			return
		}

		if len(handshake.GetKey()) < insecureSymmKeySize {
			s.logger.Printf("error while validating HelloVerify record key: %s", ErrInsecureEncryptionKeySize)
			return
		}

		var token []byte
		if len(r.Extra) > 0 {
			token, err = s.symmCrypto.Decrypt(r.Extra, handshake.GetKey())
			if err != nil {
				s.logger.Printf("error while decrypting HelloVerify record token: %s", err)
				return
			}
		}

		var ID string
		ID, err = s.authClient.Authenticate(ctx, token)
		if err != nil {
			s.logger.Printf("error while authenticating client token: %s", err)
			return
		}

		var cl *Client
		cl, err = s.registerClient(addr, ID, handshake.GetKey())
		if err != nil {
			s.logger.Printf("error while registering client: %s", err)
			return
		}

		serverHandshakeHello := s.transcoder.NewHandshakeRecord()
		serverHandshakeHello.SetSessionId(cl.sessionID)
		serverHandshakeHello.SetTimestamp(time.Now().UnixNano() / int64(time.Millisecond))

		var handshakePayload []byte
		handshakePayload, err = s.transcoder.MarshalHandshake(serverHandshakeHello)
		if err != nil {
			s.logger.Printf("error while marshaling server hello record: %s", err)
			return
		}

		err = s.sendToClient(cl, HandshakeServerHelloRecordType, handshakePayload)
		if err != nil {
			s.logger.Printf("error while sending server hello record: %s", err)
			return
		}
	}
}

// handlePingRecord handles ping record and sends pong response
func (s *Server) handlePingRecord(ctx context.Context, addr *net.UDPAddr, r *record) {
	cl, ok := s.findClientByAddr(addr)
	if !ok {
		s.logger.Printf("error while authenticating ping record: %s", ErrClientAddressIsNotRegistered)
		return
	}

	pong := s.transcoder.NewPongRecord()
	pong.SetReceivedAt(time.Now().UnixNano())

	var payload []byte
	var err error
	payload, err = s.symmCrypto.Decrypt(r.Body, cl.eKey)
	if err != nil {
		s.logger.Printf("error while decrypting ping record: %s", err)
		return
	}

	var sessionID, body []byte
	sessionID, body, err = parseSessionID(payload, len(cl.sessionID))
	if err != nil {
		s.logger.Printf("error while parsing session id for ping: %s", err)
		return
	}

	if !cl.ValidateSessionID(sessionID) {
		s.logger.Printf("error while validating session id for ping: %s", ErrClientSessionNotFound)
		s.unAuthenticated(addr)
		return
	}

	var ping encoding.PingRecord
	ping, err = s.transcoder.UnmarshalPing(body)
	if err != nil {
		s.logger.Printf("error while unmarshaling ping record: %s", err)
		return
	}

	pong.SetPingSentAt(ping.GetSentAt())
	pong.SetSentAt(time.Now().UnixNano())

	var pongPayload []byte
	pongPayload, err = s.transcoder.MarshalPong(pong)
	if err != nil {
		s.logger.Printf("error while marshaling pong record: %s", err)
		return
	}

	err = s.sendToClient(cl, PongRecordType, pongPayload)
	if err != nil {
		s.logger.Printf("error while sending pong record: %s", err)
		return
	}

	now := time.Now()
	cl.Lock()
	cl.lastHeartbeat = &now
	cl.Unlock()
}

// handleCustomRecord handle custom record with authorizing the record and call the handler func if is set
func (s *Server) handleCustomRecord(ctx context.Context, addr *net.UDPAddr, r *record) {
	cl, ok := s.findClientByAddr(addr)
	if !ok {
		s.logger.Printf("error while authenticating other type record: %s", ErrClientAddressIsNotRegistered)
		s.unAuthenticated(addr)
		return
	}

	payload, err := s.symmCrypto.Decrypt(r.Body, cl.eKey)
	if err != nil {
		s.logger.Printf("error while decrypting other type record: %s", err)
		return
	}

	var sessionID, body []byte
	sessionID, body, err = parseSessionID(payload, len(cl.sessionID))
	if err != nil {
		s.logger.Printf("error while parsing session id for ping: %s", err)
		return
	}

	if !cl.ValidateSessionID(sessionID) {
		s.logger.Printf("error while validating client session for other type record: %s", ErrClientSessionNotFound)
		s.unAuthenticated(addr)
		return
	}

	if s.handler != nil {
		s.handler(cl.ID, r.Type, body)
	}

	now := time.Now()
	cl.Lock()
	cl.lastHeartbeat = &now
	cl.Unlock()
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
	sessionID, err := s.sessionManager.GenerateSessionID(addr, ID)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	cl := &Client{
		ID:            ID,
		sessionID:     sessionID,
		addr:          addr,
		eKey:          eKey,
		lastHeartbeat: &now,
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
	payload, err := s.symmCrypto.Encrypt(payload, client.eKey)
	if err != nil {
		return err
	}
	payload = composeRecordBytes(typ, s.protocolVersion, payload)
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

func (s *Server) clientGarbageCollection() {
	for {
		select {
		case <-s.garbageCollectionStop:
			if s.garbageCollectionTicker != nil {
				s.garbageCollectionTicker.Stop()
			}
			break
		case <-s.garbageCollectionTicker.C:
			for _, c := range s.clients {
				if c.lastHeartbeat != nil && time.Now().After(c.lastHeartbeat.Add(s.heartbeatExpiration)) {
					delete(s.clients, c.ID)
					delete(s.sessions, fmt.Sprintf("%s_%d", c.addr.IP.String(), c.addr.Port))
				}
			}
		}
	}
}

// a method to broadcast byte array to all registered Clients
func (s *Server) BroadcastToClients(typ byte, payload []byte) {
	for _, cl := range s.clients {
		s.wg.Add(1)
		go func(c *Client) {
			defer s.wg.Done()
			err := s.sendToClient(c, typ, payload)
			if err != nil {
				s.logger.Printf("error while writing to the client: %s", err)
			}
		}(cl)
	}
}

func (s *Server) unAuthenticated(addr *net.UDPAddr) {
	payload := composeRecordBytes(UnAuthenticated, s.protocolVersion, []byte{})
	err := s.sendToAddr(addr, payload)
	if err != nil {
		s.logger.Printf("error while sending UnAuthenticated record to the client: %s", err)
		return
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

// WithProtocolVersion sets the server protocol version
func WithProtocolVersion(major, minor uint8) Option {
	return func(s *Server) {
		s.protocolVersion = [2]byte{major, minor}
	}
}

// WithHeartbeatExpiration sets the server heartbeat expiration option
func WithHeartbeatExpiration(t time.Duration) Option {
	return func(s *Server) {
		s.heartbeatExpiration = t
	}
}

// WithMinimumPayloadSize sets the minimum payload size option
func WithMinimumPayloadSize(i int) Option {
	return func(s *Server) {
		s.minimumPayloadSize = i
	}
}

// WithReadBufferSize sets the read buffer size option
func WithReadBufferSize(i int) Option {
	return func(s *Server) {
		s.readBufferSize = i
	}
}

// WithSymmetricCrypto sets the symmetric cryptography implementation
func WithSymmetricCrypto(sc crypto.Symmetric) Option {
	return func(s *Server) {
		s.symmCrypto = sc
	}
}

// WithAsymmetricCrypto sets the asymmetric cryptography implementation
func WithAsymmetricCrypto(ac crypto.Asymmetric) Option {
	return func(s *Server) {
		s.asymmCrypto = ac
	}
}

// WithTranscoder sets the transcoder implementation
func WithTranscoder(t encoding.Transcoder) Option {
	return func(s *Server) {
		s.transcoder = t
	}
}

// WithAuthClient sets the auth client implementation
func WithAuthClient(ac AuthClient) Option {
	return func(s *Server) {
		s.authClient = ac
	}
}

// WithLogger sets the logger
func WithLogger(l *log.Logger) Option {
	return func(s *Server) {
		s.logger = l
	}
}
