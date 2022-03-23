package udpsocket

import (
	"bytes"
	"context"
	"crypto/rsa"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/theredrad/udpsocket/crypto"
	"github.com/theredrad/udpsocket/encoding"
	"github.com/theredrad/udpsocket/encoding/pb"
	mocks "github.com/theredrad/udpsocket/mocks"
	"net"
	"testing"
	"time"
)

var (
	serverAddr = &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 9001}
	clientAddr = &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 9002}

	validToken  = []byte("valid_token")
	validUserID = "valid_user_id"

	aesKey        = []byte{113, 110, 25, 53, 11, 53, 68, 33, 17, 36, 22, 7, 125, 11, 35, 16, 83, 61, 59, 49, 31, 22, 69, 17, 24, 125, 11, 35, 16, 83, 61, 59}
	clientRandom  = []byte{12, 101, 30, 21, 8, 45, 86, 10, 125, 9, 49, 31, 22, 69, 36, 22, 7, 12, 83, 61, 5, 17, 24, 125, 11, 35, 15, 11, 35, 16, 6, 71, 19, 13}
	clientRandom2 = []byte{12, 101, 30, 21, 8, 45, 86, 10, 125, 9, 49, 31, 22, 69, 36, 22, 7, 12, 83, 61, 5, 17, 24, 125, 11, 35, 15, 11, 35, 16, 6, 71, 19, 10}
	clientVersion = "0.1"

	testRecordType byte = 13
)

type udpRecord struct {
	N     int
	Error error
	Addr  *net.UDPAddr
	Body  []byte
}

type clientConfig struct {
	authClient           AuthClient
	transcoder           encoding.Transcoder
	symmCrypto           crypto.Symmetric
	asymmCrypto          *crypto.RSAEncryptor
	readBufferSize       int
	minimumPayloadSize   int
	heartbeatExpiration  time.Duration
	protocolVersionMajor uint8
	protocolVersionMinor uint8
	serverAddr           *net.UDPAddr
	aesKey               []byte
	sessionManager       *sessionManager
}

type client struct {
	conn   *net.UDPConn
	config *clientConfig
}

func newClient(a AuthClient, conn *net.UDPConn, pk *rsa.PrivateKey, sm *sessionManager) *client {
	return &client{
		conn: conn,
		config: &clientConfig{
			serverAddr:           serverAddr,
			aesKey:               aesKey,
			asymmCrypto:          crypto.NewRSAEncryptorFromPK(&pk.PublicKey),
			authClient:           a,
			transcoder:           &pb.Protobuf{},
			symmCrypto:           crypto.NewAES(crypto.AES_CBC),
			readBufferSize:       2048,
			minimumPayloadSize:   4,
			protocolVersionMajor: 0,
			protocolVersionMinor: 1,
			sessionManager:       sm,
		},
	}
}

func (c *client) handshake(h *pb.Handshake) error {
	return c.writeHandshake(h, nil)
}

func (c *client) helloVerify(h *pb.Handshake, token []byte) error {
	return c.writeHandshake(h, token)
}

func (c *client) writeHandshake(h *pb.Handshake, extra []byte) error {
	msg, err := c.composeHandshakeRecord(h, extra)
	if err != nil {
		return err
	}

	_, err = c.conn.WriteToUDP(msg, c.config.serverAddr)
	if err != nil {
		return err
	}
	return nil
}

func (c *client) writeRecord(typ byte, sessionID, payload []byte) error {
	msg, err := c.composeRecord(typ, sessionID, payload)
	if err != nil {
		return err
	}

	_, err = c.conn.WriteToUDP(msg, c.config.serverAddr)
	if err != nil {
		return err
	}
	return nil
}

func (c *client) read(recordChan chan *udpRecord, timeout time.Duration) error {
	err := c.conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return err
	}
	buf := make([]byte, 2048)
	n, addr, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		return err
	}
	recordChan <- &udpRecord{
		N:     n,
		Addr:  addr,
		Error: err,
		Body:  buf,
	}
	return nil
}

func (c *client) waitForIncomingRecord(ctx context.Context, recordChan chan *udpRecord) (byte, []byte, error) {
	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case rec := <-recordChan:
		msg := rec.Body[:rec.N]
		msgBody := msg[3:]
		d, err := c.config.symmCrypto.Decrypt(msgBody, c.config.aesKey)
		if err != nil {
			return msg[0], nil, err
		}
		return msg[0], d, nil
	}
}

func (c *client) composeHandshakeRecord(h encoding.HandshakeRecord, extra []byte) ([]byte, error) {
	p, err := c.config.transcoder.MarshalHandshake(h)
	if err != nil {
		return nil, err
	}

	p, err = c.config.asymmCrypto.Encrypt(p)
	if err != nil {
		return nil, err
	}

	l := len(p)
	s1 := byte(l % 256)
	l = len(p) / 256
	s2 := byte(l % 256)

	p = append([]byte{HandshakeClientHelloRecordType, c.config.protocolVersionMinor, c.config.protocolVersionMajor, s2, s1}, p...)
	if len(extra) > 0 {
		extra, err = c.config.symmCrypto.Encrypt(extra, c.config.aesKey)
		if err != nil {
			return nil, err
		}
		return append(p, extra...), nil
	}
	return p, nil
}

func (c *client) composeRecord(typ byte, sessionID, payload []byte) ([]byte, error) {
	p := append(sessionID, payload...)

	p, err := c.config.symmCrypto.Encrypt(p, c.config.aesKey)
	if err != nil {
		return nil, err
	}

	p = append([]byte{typ, c.config.protocolVersionMinor, c.config.protocolVersionMajor}, p...)
	return p, nil
}

func listenUDP(t *testing.T, addr *net.UDPAddr) (*net.UDPConn, func()) {
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Errorf("expected server conn, got err: %s", err)
		t.FailNow()
	}

	return conn, func() {
		conn.Close()
	}
}

func newServerConfig(a AuthClient, pk *rsa.PrivateKey) []Option {
	return []Option{
		WithAuthClient(a),
		WithTranscoder(&pb.Protobuf{}),
		WithSymmetricCrypto(crypto.NewAES(crypto.AES_CBC)),
		WithAsymmetricCrypto(crypto.NewRSAFromPK(pk)),
		WithReadBufferSize(2048),
		WithMinimumPayloadSize(4),
		WithProtocolVersion(1, 0),
	}
}

func TestServer_Handshake(t *testing.T) {
	serverConn, serverClose := listenUDP(t, serverAddr)
	defer serverClose()

	pk, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Errorf("expected new private key, got err: %s", err)
		t.FailNow()
	}

	authClient := authMock(t)
	cfg := newServerConfig(authClient, pk)
	server, err := NewServer(serverConn, cfg...)
	if err != nil {
		t.Errorf("expected new server, got err: %s", err)
		t.FailNow()
	}
	go server.Serve()

	clientConn, clientClose := listenUDP(t, clientAddr)
	defer clientClose()

	cl := newClient(authClient, clientConn, pk, server.sessionManager)

	tests := []struct {
		name         string
		req          func() *pb.Handshake
		wantErr      bool
		err          error
		wantType     byte
		validateBody func(*pb.Handshake) error
		token        []byte
	}{
		{
			name: "empty_aes_key",
			req: func() *pb.Handshake {
				return &pb.Handshake{}
			},
			wantErr: true,
		},
		{
			name: "insecure_aes_key",
			req: func() *pb.Handshake {
				return &pb.Handshake{
					Key: []byte{33, 51, 63},
				}
			},
			wantErr: true,
		},
		{
			name: "ok",
			req: func() *pb.Handshake {
				return &pb.Handshake{
					Key:           cl.config.aesKey,
					Random:        clientRandom,
					ClientVersion: clientVersion,
				}
			},
			wantErr:  false,
			wantType: HandshakeHelloVerifyRecordType,
			validateBody: func(h *pb.Handshake) error {
				if len(h.Cookie) == 0 {
					return errors.New("expected cookie, got empty")
				}
				return nil
			},
		},
		{
			name: "hello_verify_different_random",
			req: func() *pb.Handshake {
				return &pb.Handshake{
					Key:           cl.config.aesKey,
					Random:        clientRandom2,
					ClientVersion: clientVersion,
					Cookie:        cl.config.sessionManager.GetAddrCookieHMAC(clientAddr, []byte(clientVersion), nil, clientRandom),
				}
			},
			wantErr: true,
		},
		{
			name: "hello_verify_empty_aes_key",
			req: func() *pb.Handshake {
				return &pb.Handshake{
					Random:        clientRandom,
					ClientVersion: clientVersion,
					Cookie:        cl.config.sessionManager.GetAddrCookieHMAC(clientAddr, []byte(clientVersion), nil, clientRandom),
				}
			},
			wantErr: true,
		},
		{
			name: "hello_verify_wrong_cookie",
			req: func() *pb.Handshake {
				return &pb.Handshake{
					Key:           cl.config.aesKey,
					Random:        clientRandom,
					ClientVersion: clientVersion,
					Cookie:        []byte{0, 1, 2, 3},
				}
			},
			wantErr: true,
		},
		{
			name: "server_hello",
			req: func() *pb.Handshake {
				return &pb.Handshake{
					Key:           cl.config.aesKey,
					Random:        clientRandom,
					ClientVersion: clientVersion,
					Cookie:        cl.config.sessionManager.GetAddrCookieHMAC(clientAddr, []byte(clientVersion), nil, clientRandom),
				}
			},
			wantErr:  false,
			wantType: HandshakeServerHelloRecordType,
			validateBody: func(h *pb.Handshake) error {
				if len(h.SessionId) == 0 {
					return errors.New("expected session id, got empty")
				}
				return nil
			},
			token: validToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err = cl.writeHandshake(tt.req(), tt.token)
			if err != nil {
				t.Logf("expected sent handshake record, got error: %s", err)
				t.FailNow()
			}

			recChan := make(chan *udpRecord, 1)
			go cl.read(recChan, 500*time.Millisecond)

			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			typ, m, err := cl.waitForIncomingRecord(ctx, recChan)
			if (err != nil) != tt.wantErr {
				t.Logf("want error: %t, got error: %v", tt.wantErr, err)
				t.FailNow()
			}

			if !tt.wantErr {
				if typ != tt.wantType {
					t.Logf("want %d type, got: %d", tt.wantType, typ)
					t.FailNow()
				}

				var h pb.Handshake
				err = cl.config.transcoder.Unmarshal(m, &h)
				if err != nil {
					t.Logf("expected unmarshaled messsage, got error: %d", err)
					t.FailNow()
				}

				err = tt.validateBody(&h)
				if err != nil {
					t.Logf("expected valid messsage, got error: %d", err)
					t.FailNow()
				}
			}
		})
	}
}

func TestServer_Timeout(t *testing.T) {
	serverConn, serverClose := listenUDP(t, serverAddr)
	defer serverClose()

	pk, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Errorf("expected new private key, got err: %s", err)
		t.FailNow()
	}

	authClient := authMock(t)
	cfg := newServerConfig(authClient, pk)
	server, err := NewServer(serverConn, append(cfg, WithHeartbeatExpiration(1*time.Second))...)
	if err != nil {
		t.Errorf("expected new server, got err: %s", err)
		t.FailNow()
	}
	go server.Serve()

	callbackChan := make(chan byte, 1)
	callbackFunc := func(id string, t byte, p []byte) {
		callbackChan <- t
	}
	server.SetHandler(callbackFunc)

	clientConn, clientClose := listenUDP(t, clientAddr)
	defer clientClose()

	cl := newClient(authClient, clientConn, pk, server.sessionManager)

	tests := []struct {
		name    string
		sleep   time.Duration
		wantErr bool
		loop    int
	}{
		{
			name:    "valid_connection",
			wantErr: false,
			loop:    10,
			sleep:   200 * time.Millisecond,
		},
		{
			name:    "timeout_connection",
			sleep:   2 * time.Second,
			wantErr: true,
		},
	}

	validHelloVerifyRecord := &pb.Handshake{
		Key:           cl.config.aesKey,
		Random:        clientRandom,
		ClientVersion: clientVersion,
		Cookie:        cl.config.sessionManager.GetAddrCookieHMAC(clientAddr, []byte(clientVersion), nil, clientRandom),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err = cl.writeHandshake(validHelloVerifyRecord, validToken)
			if err != nil {
				t.Logf("expected sent handshake record, got error: %s", err)
				t.FailNow()
			}

			recChan := make(chan *udpRecord, 1)
			go cl.read(recChan, 500*time.Millisecond)

			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			typ, m, err := cl.waitForIncomingRecord(ctx, recChan)
			if err != nil {
				t.Logf("want handshake server hello, got error: %s", err)
				t.FailNow()
			}

			if typ != HandshakeServerHelloRecordType {
				t.Logf("want handshake hello record type, got wrong type: %d", typ)
				t.FailNow()
			}

			if tt.loop <= 0 {
				tt.loop = 1
			}

			t.Logf("sending records for %d time(s) with %s sleep time", tt.loop, tt.sleep)
			for i := 0; i < tt.loop; i++ {
				if tt.sleep > 0 {
					time.Sleep(tt.sleep)
				}

				var h pb.Handshake
				err = cl.config.transcoder.Unmarshal(m, &h)
				if err != nil {
					t.Logf("expected unmarshaled messsage, got error: %d", err)
					t.FailNow()
				}

				err = cl.writeRecord(testRecordType, h.SessionId, []byte{1, 2, 3})
				if err != nil {
					t.Logf("expected write record, got error: %d", err)
					t.FailNow()
				}

				ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
				err = waitForCallback(ctx, callbackChan)
				if (err != nil) != tt.wantErr {
					t.Errorf("want error: %t, got: %v", tt.wantErr, err)
					t.FailNow()
				}
				cancel()
			}
		})
	}
}

func TestServer_Stop(t *testing.T) {
	serverConn, serverClose := listenUDP(t, serverAddr)
	defer serverClose()

	pk, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Errorf("expected new private key, got err: %s", err)
		t.FailNow()
	}

	authClient := authMock(t)
	cfg := newServerConfig(authClient, pk)
	server, err := NewServer(serverConn, append(cfg, WithHeartbeatExpiration(1*time.Second))...)
	if err != nil {
		t.Errorf("expected new server, got err: %s", err)
		t.FailNow()
	}
	go server.Serve()

	tests := []struct {
		name     string
		preFunc  func()
		postFunc func()
		wantErr  bool
	}{
		{
			name: "normal",
			preFunc: func() {
				go server.Serve()
			},
			postFunc: func() {
				server.Stop()
			},
			wantErr: false,
		},
		{
			name: "continuous_start_stop",
			preFunc: func() {
				go server.Serve()
				time.Sleep(200 * time.Millisecond)
				server.Stop()
				time.Sleep(200 * time.Millisecond)
				go server.Serve()
			},
			postFunc: func() {
				server.Stop()
			},
			wantErr: false,
		},
		{
			name: "stop",
			preFunc: func() {
				go server.Serve()
				time.Sleep(200 * time.Millisecond)
				server.Stop()
			},
			wantErr: true,
		},
	}

	clientConn, clientClose := listenUDP(t, clientAddr)
	defer clientClose()

	cl := newClient(authClient, clientConn, pk, server.sessionManager)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.preFunc != nil {
				tt.preFunc()
			}

			err = cl.writeHandshake(&pb.Handshake{
				Key: cl.config.aesKey,
			}, nil)
			if err != nil {
				t.Logf("expected sent handshake record, got error: %s", err)
				t.FailNow()
			}

			recChan := make(chan *udpRecord, 1)
			go cl.read(recChan, 500*time.Millisecond)

			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			_, _, err := cl.waitForIncomingRecord(ctx, recChan)
			if (err != nil) != tt.wantErr {
				t.Logf("want error: %t, got: %v", tt.wantErr, err)
				t.FailNow()
			}

			if tt.postFunc != nil {
				tt.postFunc()
			}
		})
	}
}

func TestServer_BroadcastToClients(t *testing.T) {
	serverConn, serverClose := listenUDP(t, serverAddr)
	defer serverClose()

	pk, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Errorf("expected new private key, got err: %s", err)
		t.FailNow()
	}

	authClient := authMock(t)
	cfg := newServerConfig(authClient, pk)
	server, err := NewServer(serverConn, append(cfg, WithHeartbeatExpiration(1*time.Second))...)
	if err != nil {
		t.Errorf("expected new server, got err: %s", err)
		t.FailNow()
	}
	go server.Serve()

	clientConn, clientClose := listenUDP(t, clientAddr)
	defer clientClose()

	cl := newClient(authClient, clientConn, pk, server.sessionManager)

	_, err = server.registerClient(clientAddr, uuid.New().String(), aesKey)
	if err != nil {
		t.Errorf("expected new client, got err: %s", err)
		t.FailNow()
	}

	recChan := make(chan *udpRecord, 1)
	go cl.read(recChan, 500*time.Millisecond)

	var msgType byte = 16
	body := []byte{1, 5, 9}
	server.BroadcastToClients(msgType, body)
	server.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	typ, b, err := cl.waitForIncomingRecord(ctx, recChan)
	if err != nil {
		t.Logf("expected broadcast message, got: %v", err)
		t.FailNow()
	}

	if typ != msgType || !bytes.Equal(body, b) {
		t.Logf("expected broadcast message, got unexpected messsage")
		t.FailNow()
	}
}

func BenchmarkServer_handleHandshake(b *testing.B) {
	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		b.Errorf("expected server conn, got err: %s", err)
		b.FailNow()
	}
	defer serverConn.Close()

	pk, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		b.Errorf("expected new private key, got err: %s", err)
		b.FailNow()
	}

	authClient := authMock(b)
	cfg := newServerConfig(authClient, pk)
	server, err := NewServer(serverConn, append(cfg, WithHeartbeatExpiration(1*time.Second))...)
	if err != nil {
		b.Errorf("expected new server, got err: %s", err)
		b.FailNow()
	}

	_, err = server.registerClient(clientAddr, uuid.New().String(), aesKey)
	if err != nil {
		b.Errorf("expected new client, got err: %s", err)
		b.FailNow()
	}

	cl := newClient(authClient, nil, pk, server.sessionManager)
	msg, err := cl.composeHandshakeRecord(&pb.Handshake{
		Key:           cl.config.aesKey,
		Random:        clientRandom2,
		ClientVersion: clientVersion,
		Cookie:        cl.config.sessionManager.GetAddrCookieHMAC(clientAddr, []byte(clientVersion), nil, clientRandom),
	}, nil)
	if err != nil {
		b.Errorf("expected handshake record, got err: %s", err)
		b.FailNow()
	}

	b.ResetTimer()

	msg = make([]byte, 259)
	msg[0] = 1    // record type
	msg[1] = 1    // record major protocol version
	msg[2] = 0    // record minor protocol version
	msg[189] = 21 // random message
	msg[59] = 11  // random message

	for i := 0; i < b.N; i++ {
		server.handleRecord(msg, clientAddr)
	}
}

func waitForCallback(ctx context.Context, callbackChan chan byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case typ := <-callbackChan:
		if typ != testRecordType {
			return errors.New("expected callback with sent record type, got wrong type")
		}
		return nil
	}
}

func handleServerError(t *testing.T, errChan chan error) {
	for {
		uerr := <-errChan
		if uerr != nil {
			t.Errorf("errors on udp server: %s\n", uerr.Error())
		}
	}
}

func authMock(t gomock.TestReporter) AuthClient {
	ctrl := gomock.NewController(t)
	a := mocks.NewMockAuthClient(ctrl)
	a.EXPECT().Authenticate(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, token []byte) (string, error) {
		if bytes.Compare(token[:], validToken) == 0 {
			return validUserID, nil
		}
		return "", errors.New("unauthenticated")
	}).AnyTimes()
	return a
}
