// SCRAM-SHA-256 authentication
//
// Resources:
//   https://tools.ietf.org/html/rfc5802
//   https://tools.ietf.org/html/rfc8265
//   https://www.postgresql.org/docs/current/sasl-authentication.html
//
// Inspiration drawn from other implementations:
//   https://github.com/lib/pq/pull/608
//   https://github.com/lib/pq/pull/788
//   https://github.com/lib/pq/pull/833

package pgconn

import (
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgproto3"
)

func (c *PgConn) authSha256(r *readBuf) (*writeBuf, error) {
	if r.int32() != pgproto3.AuthTypeSHA256 {
		return nil, errors.New("bad auth type")
	}

	passwordStoredMethod := r.int32()
	digest := ""
	if len(c.config.Password) == 0 {
		return nil, fmt.Errorf("The server requested password-based authentication, but no password was provided.")
	}

	if passwordStoredMethod == PlainPassword || passwordStoredMethod == Sha256Password {
		random64code := string(r.next(64))
		token := string(r.next(8))
		serverIteration := r.int32()
		result := RFC5802Algorithm(c.config.Password, random64code, token, "", serverIteration, "sha256")
		if len(result) == 0 {
			return nil, fmt.Errorf("Invalid username/password,login denied.")
		}

		w := c.writeBuf('p')
		w.buf = []byte("p")
		w.pos = 1
		w.int32(4 + len(result) + 1)
		w.bytes(result)
		w.byte(0)

		return w, nil
	} else if passwordStoredMethod == Md5Password {
		s := string(r.next(4))
		digest = "md5" + md5s(md5s(c.config.Password+c.config.User)+s)

		w := c.writeBuf('p')
		w.int16(4 + len(digest) + 1)
		w.string(digest)
		w.byte(0)

		return w, nil
	} else {
		return nil, fmt.Errorf("The  password-stored method is not supported ,must be plain, md5 or sha256.")
	}
}

// Perform SCRAM authentication.
func (c *PgConn) scramSha256Auth(r *pgproto3.ReadBuf) error {
	w, err := c.authSha256((*readBuf)(r))
	if err != nil {
		return err
	}

	c.frontend.SendSha256(w.buf)
	err = c.flushWithPotentialWriteReadDeadlock()
	if err != nil {
		return err
	}

	_, err = c.receiveMessage()
	if err != nil {
		return err
	}

	return nil
}
