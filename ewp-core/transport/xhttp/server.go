package xhttp

import (
	"io"
	"net/http"
)

type ServerAdapter struct {
	reader  io.Reader
	writer  http.ResponseWriter
	flusher http.Flusher
	closed  bool
}

func NewServerAdapter(r io.Reader, w http.ResponseWriter, f http.Flusher) *ServerAdapter {
	return &ServerAdapter{
		reader:  r,
		writer:  w,
		flusher: f,
		closed:  false,
	}
}

func (a *ServerAdapter) Read() ([]byte, error) {
	buf := make([]byte, 32*1024)
	n, err := a.reader.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (a *ServerAdapter) Write(data []byte) error {
	if a.closed {
		return io.ErrClosedPipe
	}

	if _, err := a.writer.Write(data); err != nil {
		return err
	}

	if a.flusher != nil {
		a.flusher.Flush()
	}

	return nil
}

func (a *ServerAdapter) Close() error {
	a.closed = true
	return nil
}
