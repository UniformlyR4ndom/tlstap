package proxy

import (
	"errors"
	"net"
	"os"
	"sync"

	"tlstap/assert"
)

var errFlowStopped = errors.New("release worker stopped")

// chainForwarder runs the data read for one direction through that direction's interceptor chain
// and writes the result to the destination.
type chainForwarder interface {
	// forward runs data through the chain and writes the result. data is only valid during the call.
	forward(data []byte) error

	// waitDrained blocks until nothing read so far is still held by the chain, i.e. it has all been
	// written. Returns an error if the connection ends first.
	waitDrained() error

	// hasHeld reports whether the chain currently holds data.
	hasHeld() bool

	// close must be called once the direction is done.
	close()
}

// plainForwarder is the forwarder for chains without a buffering interceptor: every chunk is
// resolved synchronously.
type plainForwarder struct {
	h            *ConnHandler
	interceptors []Interceptor
	info         *ConnInfo
	dst          net.Conn
}

func (f *plainForwarder) forward(data []byte) error {
	switch out, err := f.h.intercept(f.interceptors, data, f.info); {
	case err != nil:
		return err
	case len(out) > 0:
		f.dst.Write(out)
	}

	return nil
}

func (f *plainForwarder) waitDrained() error { return nil }
func (f *plainForwarder) hasHeld() bool      { return false }
func (f *plainForwarder) close()             {}

func (h *ConnHandler) newForwarder(interceptors []Interceptor, buffering []bufferingEntry, info *ConnInfo, dst net.Conn) chainForwarder {
	if len(buffering) == 0 {
		return &plainForwarder{h: h, interceptors: interceptors, info: info, dst: dst}
	}

	return newDirFlow(h, interceptors, buffering, info, dst)
}

// dirFlow is the forwarder for a chain containing a buffering interceptor. Reading stays with the
// caller; a worker goroutine consumes the interceptor's release channel.
//
// The chain is split at the buffering interceptor. The head (up to and including it) only ever runs
// on the reader's goroutine and outside the lock, because the interceptor may block on its own
// lock while it is sending a release. The tail and the write run under mu, for both fresh and
// released data.
//
// Before a fresh chunk enters the tail, the reader has the worker process everything already on the
// release channel (sync). The worker is the channel's only receiver, so a release sent before the
// head returned can never be overtaken by the chunk's output.
type dirFlow struct {
	h            *ConnHandler
	interceptors []Interceptor
	idx          int // position of the buffering interceptor
	bi           BufferingInterceptor
	info         *ConnInfo
	dst          net.Conn

	mu sync.Mutex // serializes running the tail and writing to dst

	release    <-chan ReleasedData // only accessed by the worker
	barrierReq chan struct{}
	barrierAck chan struct{}
	processed  chan struct{} // signaled after each release the worker handled

	quit     chan struct{}
	quitOnce sync.Once
	exited   chan struct{} // closed when the worker returns
}

func newDirFlow(h *ConnHandler, interceptors []Interceptor, buffering []bufferingEntry, info *ConnInfo, dst net.Conn) *dirFlow {
	assert.Assertf(len(buffering) == 1, "Expected exactly one buffering interceptor, got %d. This is a bug.", len(buffering))
	f := &dirFlow{
		h:            h,
		interceptors: interceptors,
		idx:          buffering[0].idx,
		bi:           buffering[0].bi,
		info:         info,
		dst:          dst,
		barrierReq:   make(chan struct{}),
		barrierAck:   make(chan struct{}, 1),
		processed:    make(chan struct{}, 1),
		quit:         make(chan struct{}),
		exited:       make(chan struct{}),
	}
	f.release = f.bi.ReleaseChannel(info)

	go f.run()
	return f
}

func (f *dirFlow) run() {
	defer close(f.exited)
	for {
		select {
		case msg, ok := <-f.release:
			if !ok {
				f.release = nil // interceptor torn down; nothing more will be released
				continue
			}

			if !f.handle(msg) {
				return
			}
		case <-f.barrierReq:
			if !f.drain() {
				return
			}

			f.barrierAck <- struct{}{}
		case <-f.quit:
			return
		case <-f.h.done:
			return
		}
	}
}

// drain handles everything currently queued on the release channel. Returns false if the worker must stop.
func (f *dirFlow) drain() bool {
	for {
		select {
		case msg, ok := <-f.release:
			if !ok {
				f.release = nil
				return true
			}

			if !f.handle(msg) {
				return false
			}
		default:
			return true
		}
	}
}

// handle forwards one release through the tail. Returns false if the connection has to end.
func (f *dirFlow) handle(msg ReleasedData) bool {
	f.mu.Lock()
	err := f.releaseLocked(msg)
	f.mu.Unlock()

	if err != nil {
		if errors.Is(err, ErrAbort) {
			f.h.logger.Info("Terminating connection %d (%s -> %s). Reason: %v", f.info.ConnID, f.info.SrcEndpoint, f.info.DstEndpoint, err)
		} else {
			f.h.logger.Error("Terminating connection %d (%s -> %s). Reason: %v", f.info.ConnID, f.info.SrcEndpoint, f.info.DstEndpoint, err)
		}

		// the forwarding goroutines may be blocked in Read and would not notice otherwise
		f.h.terminate()
		return false
	}

	select {
	case f.processed <- struct{}{}:
	default:
	}

	return true
}

func (f *dirFlow) releaseLocked(msg ReleasedData) error {
	if msg.Err != nil {
		return msg.Err
	}

	out, err := f.h.interceptFrom(f.idx+1, f.interceptors, msg.Data, f.info)
	if err != nil {
		return err
	}

	f.write(out)
	return nil
}

func (f *dirFlow) write(data []byte) {
	if len(data) == 0 {
		return
	}

	if _, err := f.dst.Write(data); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		f.h.logger.Error("Connection %d (%s -> %s): failed to write %d bytes: %v", f.info.ConnID, f.info.SrcEndpoint, f.info.DstEndpoint, len(data), err)
	}
}

// sync returns once the worker has handled everything that was on the release channel when sync was called.
func (f *dirFlow) sync() error {
	select {
	case f.barrierReq <- struct{}{}:
	case <-f.exited:
		return errFlowStopped
	case <-f.h.done:
		return errFlowStopped
	}

	select {
	case <-f.barrierAck:
		return nil
	case <-f.exited:
		return errFlowStopped
	case <-f.h.done:
		return errFlowStopped
	}
}

func (f *dirFlow) forward(data []byte) error {
	out, err := f.h.interceptFrom(0, f.interceptors[:f.idx+1], data, f.info)
	if err != nil || len(out) == 0 {
		return err
	}

	if err := f.sync(); err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	out, err = f.h.interceptFrom(f.idx+1, f.interceptors, out, f.info)
	if err != nil {
		return err
	}

	f.write(out)
	return nil
}

func (f *dirFlow) waitDrained() error {
	for {
		// HasPending is checked before the barrier: once it reports false, everything held has been
		// sent on the release channel, and the barrier then makes sure it has also been written
		if !f.bi.HasPending(f.info) {
			return f.sync()
		}

		select {
		case <-f.processed:
		case <-f.exited:
			return errFlowStopped
		case <-f.h.done:
			return errFlowStopped
		}
	}
}

// hasHeld reports whether data is held or a release is still on its way to the destination.
func (f *dirFlow) hasHeld() bool {
	if f.bi.HasPending(f.info) {
		return true
	}

	f.sync()
	return false
}

func (f *dirFlow) close() {
	f.quitOnce.Do(func() { close(f.quit) })
}
