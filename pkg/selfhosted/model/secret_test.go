package model

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

var _ = Suite(&secretColumnSuite{})

type secretColumnSuite struct {
}

func (s *secretColumnSuite) SetUpTest(c *C) {
}

func testEncDec(c *C, plaintext string, key string) string {
	enc, err := Encrypt([]byte(plaintext), key)
	c.Assert(err, IsNil)
	c.Assert(enc, NotNil)

	pt, err := Decrypt(enc, key)
	c.Assert(err, IsNil)
	c.Assert(string(pt), Equals, plaintext)

	return enc
}

func (s *secretColumnSuite) TestFull(c *C) {
	key := "abcdef123"
	plaintext := "this is a test"

	enc := testEncDec(c, plaintext, key)

	_, err := Decrypt(enc, key[:6])
	c.Assert(err, NotNil)

	_, err = Decrypt(enc, "badkey")
	c.Assert(err, NotNil)
}

func (s *secretColumnSuite) TestSizeKey(c *C) {
	plaintext := "this is a test"

	_ = testEncDec(c, plaintext, "x")
	longKey := "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed imperdiet magna libero"
	enc := testEncDec(c, plaintext, longKey)
	enc2 := testEncDec(c, plaintext, longKey[:32])
	c.Assert(enc, Not(Equals), enc2)
}

func (s *secretColumnSuite) TestSizeData(c *C) {
	plaintext := `Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.`

	_ = testEncDec(c, string(plaintext), "x")
}
