package selfhosted

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/dsggregory/yubiv/pkg/common"

	yubidb "github.com/dsggregory/yubiv/pkg/selfhosted/database"
	"github.com/dsggregory/yubiv/pkg/selfhosted/model"
	yubitest "github.com/dsggregory/yubiv/pkg/test"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

var _ = Suite(&YubiSuite{})

type YubiSuite struct {
	db *yubidb.MapDb
}

func (s *YubiSuite) SetUpTest(c *C) {
	// some test data generated using https://github.com/Yubico/yubico-c/blob/master/ykgenerate.1.txt
	s.db = yubitest.MapDbFromTestTokens()
}

func (s *YubiSuite) TestReadToken(c *C) {
	y, err := NewYubiAuth("")
	c.Assert(err, Equals, nil)
	rdr := strings.NewReader(yubitest.TestTokens[0].Token(0))
	b := y.ReadTokenData(rdr)
	c.Assert(b, Equals, false)
	c.Assert(y.done, Equals, false)
	c.Assert(y.Token(), Equals, yubitest.TestTokens[0].Token(0))
	b = y.ReadTokenData(strings.NewReader("\r"))
	c.Assert(b, Equals, true) // done
	c.Assert(y.done, Equals, true)
	c.Assert(y.Token(), Equals, yubitest.TestTokens[0].Token(0))
	y.ReadTokenData(strings.NewReader("should not be added since done"))
	c.Assert(y.done, Equals, true)
	c.Assert(y.Token(), Equals, yubitest.TestTokens[0].Token(0))
}

func (s *YubiSuite) readUser() *model.YubiUser {
	user, _ := s.db.Get(yubitest.TestTokens[0].Pub[:PubLen])
	return user
}

func (s *YubiSuite) TestShvValidateOTP(c *C) {
	otp := `kuukuubuucbibdtjlbkknuknrgchgedt`
	secret := `c54667d48722eae8c582c6ff5e8588f9`

	otp = yubitest.TestTokens[0].OTPs[0]
	secret = yubitest.TestTokens[0].Secret
	user := model.YubiUser{Secret: model.ColumnSecret(secret)}
	tok, err := ShvValidateOTP(user, []byte(otp))
	c.Assert(err, IsNil)
	c.Assert(tok, NotNil)
}

func (s *YubiSuite) TestSelfHosted(c *C) {
	y, err := NewYubiAuth("")
	c.Assert(err, Equals, nil)
	y.db = s.db
	y.SetToken(yubitest.TestTokens[0].Token(0))
	_, err = y.Validate()
	c.Assert(err, Equals, nil)
	user := s.readUser()
	c.Assert(user.Session, Equals, int64(1))

	// validating the same token should fail
	_, err = y.Validate()
	c.Assert(err, NotNil)
	c.Assert(err, Equals, common.REPLAYED_OTP)

	// validating a subsequent token should succeed
	y.SetToken(yubitest.TestTokens[0].Token(1))
	_, err = y.Validate()
	c.Assert(err, IsNil)
	user = s.readUser()
	c.Assert(user.Session, Equals, int64(2))

	// validating an unknown yubikey's token - yubikey not in DB
	y.SetToken("ccccccj0000000000000000000000000000000000000")
	_, err = y.Validate()
	c.Assert(err, NotNil)
	c.Assert(err, Equals, common.UNREGISTERED_USER)
}

func (s *YubiSuite) ExampleNewYubiAuth(c *C) {
	y, err := NewYubiAuth("")
	c.Assert(err, Equals, nil)

	// this reads from a yubi press from stdin
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter text: ")
	otp, err := reader.ReadString('\n')
	c.Assert(err, IsNil)
	y.SetToken(otp)

	user, err := y.Validate()
	c.Assert(err, IsNil)
	c.Assert(user, NotNil)
}
