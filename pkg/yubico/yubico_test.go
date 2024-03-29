package yubico

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dsggregory/yubiv/pkg/common"
	"github.com/dsggregory/yubiv/pkg/selfhosted"

	yubidb "github.com/dsggregory/yubiv/pkg/selfhosted/database"

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

func (s *yubicoSuite) TestNewYubiClient(c *C) {
	_, err := NewYubiClient(WithAPIEnvironment())
	c.Assert(err, NotNil)

	apiKey := "bar"

	// apikey is not base64
	_, err = NewYubiClient(WithAPICreds("foo", apiKey))
	c.Assert(err, NotNil)

	bApiKey := base64.StdEncoding.EncodeToString([]byte(apiKey))
	y, err := NewYubiClient(WithAPICreds("foo", bApiKey))
	c.Assert(err, IsNil)
	c.Assert(y.id, Equals, "foo")
	c.Assert(bytes.Equal(y.apiKey, []byte(apiKey)), Equals, true)

	server := "test.domain.com"
	y, err = NewYubiClient(
		WithAPIServers([]string{server}),
		WithAPICreds("foo", bApiKey),
	)
	c.Assert(err, IsNil)
	c.Assert(len(y.servers), Equals, 1)
	c.Assert(y.servers[0], Equals, server)
}

func (s *yubicoSuite) TestYubioServerVerify(c *C) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// leverages selfhosted to simulate response from https://api.yubico.com/wsapi/2.0/verify
		otp := r.URL.Query().Get("otp")
		rnonce := r.URL.Query().Get("nonce")
		status := common.OK.String()
		user, err := s.mapDB.Get(otp[:common.TokenIDLen])
		if err != nil {
			status = common.NO_SUCH_CLIENT.String()
		} else {
			_, err = selfhosted.ShvValidateOTP(*user, []byte(otp))
			if err != nil {
				status = err.Error()
			}
		}
		tms := time.Now().Format("2006-01-02T15:04:05")
		_, _ = fmt.Fprintf(w, `
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
	res, err := yc.VerifyOTP(yubitest.TestTokens[0].Token(0))
	c.Assert(err, IsNil)
	c.Assert(res, NotNil)

	// should fail unable to look up the yubikey ID
	res, err = yc.VerifyOTP("unknown ID+2" + yubitest.TestTokens[0].Token(0)[common.TokenIDLen:])
	c.Assert(err, NotNil)
	c.Assert(err.Error(), Equals, common.NO_SUCH_CLIENT.String())
}
