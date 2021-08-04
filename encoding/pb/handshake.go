package pb

func (h *Handshake) SetSessionId(s []byte) {
	h.SessionId = s
}

func (h *Handshake) SetCookie(c []byte) {
	h.Cookie = c
}

func (h *Handshake) SetCipherSuites(b []byte) {
	h.CipherSuites = b
}

func (h *Handshake) SetTimestamp(t int64) {
	h.Timestamp = t
}
