package proxy

import "bytes"

type cappedBuffer struct {
	buf      bytes.Buffer
	max      int64
	overflow bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.overflow {
		return len(p), nil
	}
	remaining := c.max - int64(c.buf.Len())
	if remaining <= 0 {
		c.overflow = true
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		_, _ = c.buf.Write(p[:remaining])
		c.overflow = true
		return len(p), nil
	}
	_, _ = c.buf.Write(p)
	return len(p), nil
}

func (c *cappedBuffer) Bytes() []byte { return c.buf.Bytes() }
