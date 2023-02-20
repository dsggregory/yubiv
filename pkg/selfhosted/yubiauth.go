package selfhosted

import (
	"bytes"
	"fmt"
	"io"

	"github.com/dsggregory/yubiv/pkg/common"

	yubidb "github.com/dsggregory/yubiv/pkg/selfhosted/database"

	"github.com/dsggregory/yubiv/pkg/selfhosted/model"
	log "github.com/sirupsen/logrus"
)

type YubiAuth struct {
	db      yubidb.Databaser
	done    bool
	token   bytes.Buffer
	nResets int
}

func (y *YubiAuth) GetDB() yubidb.Databaser {
	return y.db
}

func (y *YubiAuth) Token() string {
	return y.token.String()
}

func (y *YubiAuth) Bytes() []byte {
	return y.token.Bytes()
}

// Public the public part of the token
func (y *YubiAuth) Public() string {
	if y.token.Len() >= PubLen {
		return y.token.String()[:PubLen]
	}
	return y.token.String()
}

// Done finished reading the token?
func (y *YubiAuth) Done() bool {
	return y.done
}

// Reset make ready to read next token
func (y *YubiAuth) Reset() {
	y.nResets++
	y.done = false
	y.token.Truncate(0)
}

// GetResetCount returns the number of times Reset() has been called
func (y *YubiAuth) GetResetCount() int {
	return y.nResets
}

// RetryableError validation or other error is retryable?
func (y *YubiAuth) RetryableError(err error) bool {
	switch err {
	case common.BAD_OTP, common.UNREGISTERED_USER, common.EMPTY_YUBI_TOKEN, common.NO_SUCH_CLIENT:
		return true
	default:
		return false
	}
}

// ReadTokenData reads bytes from input until a CR is found. Returns true if the token has been fully consumed.
func (y *YubiAuth) ReadTokenData(reader io.Reader) bool {
	if y.done {
		log.Error("yubi token is already complete")
		return y.done
	}
	_, err := io.Copy(&y.token, reader)
	if err == nil {
		l := y.token.Len()
		if l > 0 && y.token.String()[l-1] == '\r' {
			y.done = true
			y.token.Truncate(l - 1) // strip the CR
			log.Debug("read full yubi token")
		}
	} else {
		log.WithError(err).Error("unable to taken data")
	}

	return y.done
}

// SetToken instead of reading a token from input, set it from a string
func (y *YubiAuth) SetToken(token string) {
	y.token.Truncate(0)
	y.token.Write([]byte(token))
	y.done = true
}

// VerifyToken is not normally called. Use Validate() instead. This simply verifies the OTP but does not
// determine if the token is registered, nor does it update token session counters in the DB.
func (y *YubiAuth) VerifyToken(user model.YubiUser, token string) (*Token, error) {
	var tokRslt *Token
	if user.Secret != "" {
		// self-hosted verification
		_, otp, err := ParseToken(token)
		if err != nil {
			return nil, err
		}
		tokRslt, err = ShvValidateOTP(user, otp)
		if err != nil {
			return nil, err
		}
		/***
		} else {
			// Using Yubico servers for token validation
			log.WithField("user", user.Email).Debug("using Yubico servers for OTP validation")
			resp, err := otpv.VerifyOTP(token)
			if err != nil {
				return nil, err
			}
			tokRslt = &Token{
				Ctr: uint16(resp.SessionCounter),
				Use: uint8(resp.SessionUse),
			}
		*/
	}

	return tokRslt, nil
}

// Validate will validate the yubikey token we read.
// Looks up yubikey ID from token to ensure user is registered.
// For the self-hosted validation, it uses the user records secret key to decrypt the token.
// Uses Yubico server validation when db is nil or user.secret is empty.
// For self-hosted, the usage count will be updated in the database when the token successfully validates.
// Returns a non-nil error if it cannot be validated or found in the database.
func (y *YubiAuth) Validate() (*model.YubiUser, error) {
	log.Debug("validating yubi token against database")
	if y.token.Len() == 0 {
		return nil, common.BAD_OTP
	}

	var user *model.YubiUser
	if y.db != nil {
		// Find the user corresponding to the public key of the token in the database
		u, err := y.db.Get(y.Public())
		if err != nil {
			return nil, fmt.Errorf("%w: %s", err, common.UNREGISTERED_USER.String())
		}
		user = u
		if user != nil && !user.IsEnabled {
			return user, common.UNREGISTERED_USER
		}

		tokRslt, err := y.VerifyToken(*user, y.token.String())
		if err != nil {
			return user, err
		}
		user.Counter = int64(tokRslt.Ctr)
		user.Session = int64(tokRslt.Use)
		err = y.db.UpdateCounts(*user)
		if err != nil {
			return user, err
		}
	} else {
		// no database, also indicates not self-hosted
		user = &model.YubiUser{}
		tokRslt, err := y.VerifyToken(*user, y.token.String())
		if err != nil {
			return user, err
		}
		user.Counter = int64(tokRslt.Ctr)
		user.Session = int64(tokRslt.Use)
	}
	return user, nil
}

// NewYubiAuth creates an instance of a Yubi Key authenticator. If dsn is not empty, it specifies an implementation of a Databaser interface where self-hosted yubikeys are stored for valid users. Otherwise, Yubi tokens are validated by the default YubiCo services in the cloud.
func NewYubiAuth(dsn string) (*YubiAuth, error) {
	var db yubidb.Databaser
	if dsn != "" {
		d, err := yubidb.NewDb(dsn)
		if err != nil {
			return nil, err
		}
		db = d
	}
	return &YubiAuth{db: db}, nil
}
