package shellforge

import (
	"bytes"
	"context"
)

func (d *Daemon) DefaultClientInitHandler(ctx context.Context, msg []byte) func(ctx context.Context, msg []byte) bool {

	return func(ctx context.Context, msg []byte) bool {
		for _, s := range d.Conf.AcceptedInitMsgs {
			if bytes.Equal(msg, []byte(s)) {
				return true
			}
		}
		return false
	}

}
