# udpsocket

I made this package to make a virtual stateful connection between the client & server using the UDP protocol for a golang game server (as you know the UDP protocol is stateless, packets may not arrive in order & there is no ACK).

The `udpsocket`  supports a mimic of DTLS handshake, cryptography, session management & authentication. It's responsible to make a secure channel between the client & server on UDP (handshake), authenticate & manage them, decrypt & encrypt the data & provide an API to send or broadcast data to the clients & listen to them.

## Using

The `udpsocket` server requires some parameters to initiate:

* An instance of `*net.UDPConn`
* An instance of `udpsocket.Config`

### Config

Passing the config object is not required & if no config object pass, the default config will be used.

#### AuthClient

An implementation of `AuthClient` interface that is used to authenticting the user token. If your server doesn't need any token-based authentication, don't pass anything, so the Server will use the default implementation of it which has no authentication.

#### Transcoder

An implementation of `Transcoder` interface that is used to encode & decode the data between the client & server. The default implementation of the `Transcoder` is `Protobuf`. The transcoder can encode & decode some default message types, like handshake & ping & also supports general `Marshal` & `Unmarshal` methods to support your custom data type.

#### Symmetric encryption

An implementation of `crypto.Symmetric` interface to encrypt & decrypt via Symmetric-keys algorithms. The default implementation uses `AES CBC` with `PKCS#7` padding.

#### Asymmetric encryption

An implementation of `crypto.Asymmetric` interface to encrypt & decrypt via public-key cryptography. The default implementation uses `RSA` with custom key size.

#### Other configs

* `ReadBufferSize`: Size of reading buffer
* `MinimumPayloadSize`: to cut the data that has not enough size (to prevent some attack methods)
* `ProtocolVersionMajor`: the protocol major version
* `ProtocolVersionMinor`: the protocol minor version



```go
package main

import (
	"context"
  "log"
	"net"
  "fmt"
   "crypto/rsa"
  
	"demo/auth"
	"demo/encoding"
	
  "github.com/theredrad/udpsocket"
  "github.com/theredrad/udpsocket/crypto"
)

var (
	pk *rsa.PrivateKey

	udpServerIP   = "127.0.0.1"
	udpServerPort = "7009"

	defaultRSAPrivateKeySize = 2048
)

func main() {
	f, err := auth.NewFirebaseClient(context.Background(), "firebase-config.json") // firebase implementation of auth client to validate firebase-issued tokens
	if err != nil {
		panic(err)
	}

	udpAddr, err = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", udpServerIP, udpServerPort))
	if err != nil {
		panic(err)
	}

	udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		panic(err)
	}
	defer udpConn.Close()


	pk, err = crypto.GenerateRSAKey(defaultRSAPrivateKeySize)
	if err != nil {
		panic(err)
	}
	
	r := crypto.NewRSAFromPK(pk) // creating a new instance of the RSA implementation
	if err != nil {
		panic(err)
	}

	a := crypto.NewAES(crypto.AES_CBC) // creating a new instance of the AES implementation

	t := &encoding.MessagePack{} // an implementation of msgpack for the Transcoder
	s, err := udpsocket.NewServer(udpConn, &udpsocket.Config{
		AuthClient: f,
		Transcoder: t,
		SymmCrypto: a,
		AsymmCrypto: r,
		ReadBufferSize: 2048,
		MinimumPayloadSize: 4,
		ProtocolVersionMajor: 0,
		ProtocolVersionMinor: 1,
	})
	if err != nil {
		panic(err)
	}
	s.SetHandler(incomingHandler)

	go func() { // handling the server errors
		for {
			uerr := <- s.Errors
			if uerr != nil {
				log.Printf("errors on udp server: %s\n", uerr.Error())
			}
		}
	}()

	go s.Serve() // start to run the server, listen to incoming records

  // TODO: need to serve the public key on HTTPS (TLS) to secure the download for the client
}

func incomingHandler(id string, t byte, p []byte) {
	// handle the incoming
}

```



## Send or broadcast a message

The server exported two methods to send a message to the client or broadcast a message for all clients. To send a message to a certain client, you must have the client ID.

* BroadcastToClients(messageType byte, payload []bytes)
* SendToClientByID(clientID string, messageType byte, payload []byte)

The payload is a Transcoder encoded message & encrypted is handled by the Server.

## Handler

The handler is a function with `func(id string, t byte, p []byte)` signature. You can set your handler function by the `SetHandler` method. This function is called when a custom type record is received & authenticated. The `id` parameter is the client ID (which is fetched from the token, or a new generated UUID if no authentication is required), the `t` parameter is the record type & the `p` parameter is the decrypted payload, you must `Unmarshal` it to your custom message type. 



## Dig deeper

## Record

Each message from the client is a `Record`. The record has a format to parse & decryption.

```
 1   0   1   1 0 2 52 91 253 115 22 78 39 28 5 192 47 211...
|-| |-| |-|  |------------------------------------------|
 a   b   c                        d

a: record type
b: record protocol major version
c: record protocol minor version
d: record body
```



### Record types

The first byte of record is the type & indicates how to parse the record. supported reserved types:

* ClientHello : `1`
* HelloVerify: `2`
* ServerHello: `3`
* Ping: `4`
* Pong: `5`

## Handshake

The handshake process is made base on a mimic of DTLS protocol, the client sends `ClientHello` record, this record contains a random bytes & AES key & encrypted by the server public key, which is needed to download on TLS, then the server generates a random cookie based on the client parameters, encrypts it with the client AES key (which is received by `ClientHello` & sends it as `HelloVerify` record. The client decrypts the record & repeats `ClientHello` message with the cookie, the record is needed to be encrypted with the server public key, then append the encrypted user token (with AES) to the record body. the server will registers the client after cookie verification & authenticates the user token & then returns a `ServerHello` record contains a random secret session ID. The handshake process is done here.

```
      Client                                   Server
      ------                                   ------
      ClientHello           ------>

                            <-----         HelloVerifyRequest
                                           (contains cookie)

      ClientHello           ------>
 (with cookie & token)
      
                            <-----           ServerHello
                                         (contains session ID)
```

## Encryption

The `Server` uses both symmetric & asymmetric encryptions to communicate with the client.

### Handshake

The `ClientHello` record (for the server) contains a secure 256 bit AES key & encrypted by the server public key, so the server could decrypt it with the private key.

The `HelloVerify` record (for the client) encrypts with the client AES key (which was decrypted before).

If user authentication is required, the client must send the user token with the `ClientHello` (a record which contains cookie too), but the asymmetric encryption has a limitation on size. for example, the RSA only is able to encrypt data to a maximum amount equal to the key size (e.g. 2048 bits = 256 bytes) & the user token size could be more, so the user token must be encypt by the client AES, then the server could decrypt it after validation of `ClientHello` record.

The handshake record structure is a little different because of using hybrid encryption. the two bytes after the protocol version bytes indicates the size of the handshake body which is encrypted by the server public key. the handshake body size is passing because of the key size, the encrypted body size depends on the RSA key size.

```
 1   0   1   1   0   2 52 91 253 115 22 78 39 28 5 192 47 211 ... 4 22 64 91 195 37 225
|-| |-| |-| |-| |-| |----------------------------------------|   |---------------------|
 a   b   c   d   e                      f                                   g

a: record type (1 => handshake)
b: record protocol major version (0 => 0.1v)
c: record protocol minor version (1 => 0.1v)
d: handshake body size ([1] 0 => 256 bytes, key size: 2048 bits) (first digit number in base of 256)
e: handshake body size (1 [0] => 256 bytes, key size: 2048 bits) (second digit number in base of 256)
f: handshake body which is encrypted by the server public key & contains the client AES key
g: user token which is encrypted by the client AES key size
```

## Other records

After a successful handshake, the server returns a secret `SessionID` in the `ServerHello` record which is encrypted by the client AES Key. The client must append the `SessionID` to the custom record bytes, then encrypt it by the AES key, add the record headers (record type & protocol version), then send the bytes to the server. The server will decrypt the record body by the client AES key (which is registered before with the IP & port of the client), then parse the `SessionID` from the decrypted body, authorize the session ID & pass the bytes to the `Handler` function. 

For `Ping` record, the server immidiently sends a `Pong` record to the client.



## TODO

- [x] Update client lastHeartBeat to close the connection on timeout (delete the client to prevent sending message on the broadcast) 
- [ ] Check the client random bytes for all zero value
- [ ] Add tests
- [ ] Check the client AES key strength
- [ ] Add throttling (rate limit, ban IP ...)
- [ ] Support cipher suites