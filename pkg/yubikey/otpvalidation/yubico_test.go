package otpvalidation

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	yubidb "github.com/dsggregory/yubiv/pkg/yubikey/database"

	yubitest "github.com/dsggregory/yubiv/pkg/test"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

var _ = Suite(&yubicoSuite{})

type yubicoSuite struct {
	mapDB *yubidb.MapDb
}

func (s *yubicoSuite) SetUpTest(c *C) {
	s.mapDB = yubitest.MapDbFromTestTokens()
}

func (s *yubicoSuite) TestYubioServerVerify(c *C) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// simulates response from https://api.yubico.com/wsapi/2.0/verify
		otp := r.URL.Query().Get("otp")
		rnonce := r.URL.Query().Get("nonce")
		status := OK.String()
		user, err := s.mapDB.Get(otp[:PubLen])
		if err != nil {
			status = NO_SUCH_CLIENT.String()
		} else {
			_, err = ShvValidateOTP(*user, []byte(otp))
			if err != nil {
				status = err.Error()
			}
		}
		tms := time.Now().Format("2006-01-02T15:04:05")
		fmt.Fprintf(w, `
status=%s
otp=%s
nonce=%s
t=%sZ0000
`,
			status, otp, rnonce, tms)
	}))
	defer ts.Close()

	yc, err := NewTestYubiClient(ts.URL)
	c.Assert(err, IsNil)

	// should verify
	res, err := yc.VerifyDefault(yubitest.TestTokens[0].Token(0))
	c.Assert(err, IsNil)
	c.Assert(res, NotNil)

	// should fail unable to lookup the yubikey ID
	res, err = yc.VerifyDefault("unknown ID" + yubitest.TestTokens[0].Token(0))
	c.Assert(err, NotNil)
	c.Assert(err.Error(), Equals, NO_SUCH_CLIENT.String())
}
