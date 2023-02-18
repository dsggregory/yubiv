package otpvalidation

/*** Verify a Yubikey OTP using Yubico servers. This works out-of-the-box with new Yubikeys using factory-configured slot #1.
See https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html
*/

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// YubiCloudServers Yubico servers that know about your factory-configured yubikey slot #1.
var YubiCloudServers = []string{
	"https://api.yubico.com/wsapi/2.0/verify",
	"https://api2.yubico.com/wsapi/2.0/verify",
	"https://api3.yubico.com/wsapi/2.0/verify",
	"https://api4.yubico.com/wsapi/2.0/verify",
	"https://api5.yubico.com/wsapi/2.0/verify",
}

// YubiClient Yubico API key info
type YubiClient struct {
	id      string
	apiKey  []byte
	servers []string
}

// VerifyRequest A request to verify a OTP
type VerifyRequest struct {
	ID        string // Required Yubico Client ID associated with API key
	OTP       string // Required OTP to validate
	H         string // Optional HMAC-SHA1 signature for the request.
	Timestamp bool   // Optional servers provides timestamp and session counter info in response
	Nonce     string // Required 16 to 40 character long string with random unique data
	SL        string // Optional value 0 to 100 indicating percentage of syncing required by client, or strings "fast" or "secure" to use server-configured values; if absent, let the server decide
	Timeout   int    // Optional number of seconds to wait for sync responses; if absent, let the server decide
}

func (v *VerifyRequest) toValues() url.Values {
	u := url.Values{
		"id":    {v.ID},
		"otp":   {v.OTP},
		"nonce": {v.Nonce},
	}

	if v.Timestamp {
		u["timestamp"] = []string{"1"}
	}

	if v.SL != "" {
		u["sl"] = []string{v.SL}
	}

	if v.Timeout != 0 {
		u["timeout"] = []string{strconv.Itoa(v.Timeout)}
	}

	return u
}

func isValidResponseHash(m map[string]string, key []byte) bool {

	// if we have no API key, or no hash was provided, then it's valid
	if len(key) == 0 || m["h"] == "" {
		return true
	}

	exp, err := base64.StdEncoding.DecodeString(m["h"])
	if err != nil {
		return false
	}

	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := hmac.New(sha1.New, key)
	var ampersand []byte
	for _, k := range keys {
		if k == "h" {
			continue
		}
		_, _ = h.Write(ampersand)
		_, _ = h.Write([]byte(k))
		_, _ = h.Write([]byte{'='})
		_, _ = h.Write([]byte(m[k]))
		ampersand = []byte{'&'}
	}

	return hmac.Equal(exp, h.Sum(nil))
}

func signRequest(req url.Values, key []byte) {
	h := hmac.New(sha1.New, key)
	u := req.Encode()
	_, _ = h.Write([]byte(u))
	sig := h.Sum(nil)
	req["h"] = []string{base64.StdEncoding.EncodeToString(sig)}
}

// VerifyResponse Response from a Yubico verify request
type VerifyResponse struct {
	// OTP one time password from the YubiKey, from request
	OTP string
	// Nonce is a random unique data, from request
	Nonce string
	// H Signature
	H []byte
	// T timestamp in UTC
	T time.Time
	// Status is the status of the operation
	Status Status
	// Timestamp YubiKey internal timestamp value when key was pressed
	Timestamp uint
	// SessionCounter YubiKey internal usage counter when key was pressed
	SessionCounter uint
	// SessionUse YubiKey internal session usage counter when key was pressed
	SessionUse uint
	// SL percentage of external validation server that replied successfully (0 to 100)
	SL int
}

// NewYubiClient creates a new Yubi Cloud client to verify future tokens.
//
// You must use your own client id and apiKey to use their servers. Refer to YubicoAPIEnvironment().
//
// See [Obtain a Yubico API Key]: https://support.yubico.com/hc/en-us/articles/360013717560-Obtaining-an-API-Key-for-YubiKey-Development
func NewYubiClient(id string, apikey string) (*YubiClient, error) {
	return NewYubiClientWithServers(id, apikey, YubiCloudServers)
}

// NewYubiClientWithServers alternative to NewYubiClient that specifies the Yubico validation servers to use
func NewYubiClientWithServers(id string, apikey string, servers []string) (*YubiClient, error) {
	if id == "" || apikey == "" {
		return nil, fmt.Errorf("yubico client requires API ID and Secret")
	}

	y := &YubiClient{id: id, servers: servers}

	key, err := base64.StdEncoding.DecodeString(apikey)
	if err != nil {
		return nil, err
	}
	y.apiKey = key

	return y, nil
}

// NewTestYubiClient a test suite function
func NewTestYubiClient(server string) (*YubiClient, error) {
	return &YubiClient{id: "test", apiKey: []byte(""), servers: []string{server}}, nil
}

func parseTimestamp(t string) (time.Time, error) {
	if len(t) < 3 {
		return time.Time{}, fmt.Errorf("time is short")
	}
	milli, _ := strconv.Atoi(t[len(t)-3:])
	t = t[:len(t)-3]
	ts, err := time.Parse("2006-01-02T15:04:05Z0", t)
	if err != nil {
		return time.Time{}, err
	}
	return ts.Add(time.Duration(milli) * time.Millisecond), nil
}

func (y *YubiClient) responseFromBody(body []byte) (*VerifyResponse, error) {

	buf := bytes.NewBuffer(body)

	scanner := bufio.NewScanner(buf)

	m := make(map[string]string)

	// Validate the input
	for scanner.Scan() {
		l := scanner.Bytes()
		s := bytes.SplitN(l, []byte{'='}, 2)
		if len(s) != 2 {
			continue
		}
		m[string(s[0])] = string(s[1])
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error parsing response: %s", err)
	}

	if !isValidResponseHash(m, y.apiKey) {
		return nil, fmt.Errorf("invalid response signature")
	}

	var err error
	r := &VerifyResponse{}
	r.OTP = m["otp"]
	r.Nonce = m["nonce"]
	r.H, _ /* err */ = base64.StdEncoding.DecodeString(m["h"]) // error ignored here because it validated in isValidResponseHash()
	r.T, err = parseTimestamp(m["t"])
	if err != nil {
		return nil, fmt.Errorf("error parsing response timestamp: %s", err)
	}

	r.Status = statusFromString(m["status"])
	if sl, ok := m["sl"]; ok {
		r.SL, err = strconv.Atoi(sl)
		if err != nil {
			return nil, fmt.Errorf("error parsing response `sl': %s", err)
		}
	}

	// optional responses
	if s, ok := m["timestamp"]; ok {
		sc, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("error parsing timestamp: %s", err)
		}
		r.Timestamp = uint(sc)
	}

	if s, ok := m["sessioncounter"]; ok {
		sc, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("error parsing sessioncounter: %s", err)
		}
		r.SessionCounter = uint(sc)
	}

	if s, ok := m["sessionuse"]; ok {
		sc, err := strconv.ParseUint(s, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("error parsing sessionuse: %s", err)
		}
		r.SessionUse = uint(sc)
	}

	return r, nil
}

// Verify generic request. See YubicoVerifyDefault() for convenience.
func (y *YubiClient) Verify(req *VerifyRequest) (*VerifyResponse, error) {

	// random server
	server := y.servers[rand.Intn(len(y.servers))]

	if req.ID == "" {
		req.ID = y.id
	}

	req.OTP = strings.Trim(req.OTP, "\n")

	values := req.toValues()

	if y.apiKey != nil {
		signRequest(values, y.apiKey)
	}

	hreq, err := http.NewRequest(http.MethodGet, server+"?"+values.Encode(), nil)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(hreq.Context(), 10*time.Second)
	defer cancel()
	hreq = hreq.WithContext(ctx)
	resp, err := http.DefaultClient.Do(hreq)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1024*4))
	if err != nil {
		return nil, err
	}

	response, err := y.responseFromBody(body)

	if err != nil {
		return nil, err
	}

	if response.OTP != req.OTP {
		return nil, errors.New("response OTP does not match")
	}
	if response.Nonce != req.Nonce {
		return nil, errors.New("response Nonce does not match")
	}

	return response, nil
}

// YubicoAPIEnvironment reads well-known environment variables to get your Yubi client API creds
func YubicoAPIEnvironment() (clientID string, secretKey string, err error) {
	clientID = os.Getenv("YUBICO_API_CLIENT_ID")
	secretKey = os.Getenv("YUBICO_API_SECRET_KEY")
	if clientID == "" || secretKey == "" {
		err = errors.New("requires YUBICO_API_CLIENT_ID and YUBICO_API_SECRET_KEY environment variables")
	}
	return
}

// VerifyDefault (with client) formats and makes a request. This is a convenience using default values.
func (y *YubiClient) VerifyDefault(otp string) (*VerifyResponse, error) {
	nb := make([]byte, 32)
	if _, err := io.ReadFull(crand.Reader, nb); err != nil {
		return nil, err
	}
	nonce := fmt.Sprintf("%x", nb)[:40] // request takes max of 40 characters for nonce

	req := VerifyRequest{
		OTP:       otp,
		Timestamp: true,
		Nonce:     nonce,
		SL:        "0",
		Timeout:   0,
	}
	resp, err := y.Verify(&req)
	if err != nil {
		return nil, err
	}
	if resp.Status != OK {
		return resp, fmt.Errorf(resp.Status.String())
	}

	return resp, nil
}

// YubicoVerifyDefault formats and makes a request. This is a convenience using default values.
func YubicoVerifyDefault(otp string) (*VerifyResponse, error) {
	apiID, apiKey, err := YubicoAPIEnvironment()
	if err != nil {
		return nil, err
	}
	c, err := NewYubiClient(apiID, apiKey)
	if err != nil {
		return nil, err
	}
	return c.VerifyDefault(otp)
}
