package server

import (
	"container/heap"
	"io"
	"sync"
)

type Packet struct {
	Payload []byte
	Seq     uint64
}

type UploadQueue struct {
	pushedPackets   chan Packet
	writeCloseMutex sync.Mutex
	heap            uploadHeap
	nextSeq         uint64
	closed          bool
	maxPackets      int
	mu              sync.Mutex
}

func NewUploadQueue(maxPackets int) *UploadQueue {
	return &UploadQueue{
		pushedPackets: make(chan Packet, maxPackets),
		heap:          uploadHeap{},
		nextSeq:       0,
		closed:        false,
		maxPackets:    maxPackets,
	}
}

func (q *UploadQueue) Push(p Packet) error {
	q.writeCloseMutex.Lock()
	defer q.writeCloseMutex.Unlock()

	if q.closed {
		return io.ErrClosedPipe
	}
	q.pushedPackets <- p
	return nil
}

func (q *UploadQueue) Close() error {
	q.writeCloseMutex.Lock()
	defer q.writeCloseMutex.Unlock()

	if !q.closed {
		q.closed = true
		close(q.pushedPackets)
	}
	return nil
}

func (q *UploadQueue) Read(b []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed && len(q.heap) == 0 {
		select {
		case _, ok := <-q.pushedPackets:
			if !ok {
				return 0, io.EOF
			}
		default:
			return 0, io.EOF
		}
	}

	if len(q.heap) == 0 {
		q.mu.Unlock()
		packet, more := <-q.pushedPackets
		q.mu.Lock()
		if !more {
			return 0, io.EOF
		}
		heap.Push(&q.heap, packet)
	}

	for len(q.heap) > 0 {
		packet := heap.Pop(&q.heap).(Packet)

		if packet.Seq == q.nextSeq {
			n := copy(b, packet.Payload)

			if n < len(packet.Payload) {
				packet.Payload = packet.Payload[n:]
				heap.Push(&q.heap, packet)
			} else {
				q.nextSeq++
			}

			return n, nil
		}

		if packet.Seq > q.nextSeq {
			if len(q.heap) > q.maxPackets {
				return 0, io.ErrShortBuffer
			}
			heap.Push(&q.heap, packet)
			
			q.mu.Unlock()
			packet2, more := <-q.pushedPackets
			q.mu.Lock()
			if !more {
				return 0, io.EOF
			}
			heap.Push(&q.heap, packet2)
		}
	}

	return 0, nil
}

func (q *UploadQueue) NextSeq() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	seq := q.nextSeq
	q.nextSeq++
	return seq
}

type uploadHeap []Packet

func (h uploadHeap) Len() int           { return len(h) }
func (h uploadHeap) Less(i, j int) bool { return h[i].Seq < h[j].Seq }
func (h uploadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *uploadHeap) Push(x any) {
	*h = append(*h, x.(Packet))
}

func (h *uploadHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
