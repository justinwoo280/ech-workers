package xhttp

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"ewp-core/transport/browser_dialer"
)

type XmuxBrowserClient struct {
	client       *browser_dialer.BrowserClient
	closed       int32
	lastActive   int64
	requestCount int64
	mu           sync.RWMutex
}

func NewXmuxBrowserClient(headers http.Header) *XmuxBrowserClient {
	return &XmuxBrowserClient{
		client:     browser_dialer.NewBrowserClient(headers),
		lastActive: time.Now().UnixNano(),
	}
}

func (x *XmuxBrowserClient) IsClosed() bool {
	if atomic.LoadInt32(&x.closed) == 1 {
		return true
	}
	return x.client.IsClosed()
}

func (x *XmuxBrowserClient) Close() error {
	atomic.StoreInt32(&x.closed, 1)
	return nil
}

func (x *XmuxBrowserClient) GetLastActiveTime() time.Time {
	nano := atomic.LoadInt64(&x.lastActive)
	return time.Unix(0, nano)
}

func (x *XmuxBrowserClient) GetRequestCount() int64 {
	return atomic.LoadInt64(&x.requestCount)
}

func (x *XmuxBrowserClient) IncrementRequestCount() {
	atomic.AddInt64(&x.requestCount, 1)
	atomic.StoreInt64(&x.lastActive, time.Now().UnixNano())
}

func (x *XmuxBrowserClient) OpenStream(ctx context.Context, url string, body io.Reader, uploadOnly bool) (io.ReadCloser, error) {
	rc, _, _, err := x.client.OpenStream(ctx, url, body, uploadOnly)
	if err == nil {
		x.IncrementRequestCount()
	}
	return rc, err
}

func (x *XmuxBrowserClient) PostPacket(ctx context.Context, url string, body io.Reader, contentLength int64) error {
	err := x.client.PostPacket(ctx, url, body, contentLength)
	if err == nil {
		x.IncrementRequestCount()
	}
	return err
}
