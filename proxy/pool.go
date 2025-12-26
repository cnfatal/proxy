package proxy

import "sync"

const KB = 1024

const (
	// BufferSize is the size of the buffers in the pool
	BufferSize = 32 * KB
	// SmallBufferSize is the size of small buffers (e.g. for sniffing)
	SmallBufferSize = 4 * KB
)

// BufferPool defines the interface for buffer management
type BufferPool interface {
	Get() []byte
	GetSmall() []byte
	Put([]byte)
}

// defaultBufferPool is the default implementation of BufferPool
type defaultBufferPool struct {
	pool      sync.Pool
	smallPool sync.Pool
}

// NewBufferPool creates a new buffer pool
func NewBufferPool() BufferPool {
	return &defaultBufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, BufferSize)
			},
		},
		smallPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, SmallBufferSize)
			},
		},
	}
}

func (p *defaultBufferPool) Get() []byte {
	return p.pool.Get().([]byte)
}

func (p *defaultBufferPool) GetSmall() []byte {
	return p.smallPool.Get().([]byte)
}

func (p *defaultBufferPool) Put(buf []byte) {
	if cap(buf) == SmallBufferSize {
		p.smallPool.Put(buf[:SmallBufferSize])
		return
	}
	if cap(buf) < BufferSize {
		return
	}
	p.pool.Put(buf[:BufferSize])
}
