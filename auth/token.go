package auth

import (
  "fmt"
  "math/rand"
  "net/http"
  "strconv"
  "time"

  "github.com/jimmc/auth/users"
)

var (
  timeNow = time.Now            // Allow overriding for unit testing.
)

var (
  tokens map[string]*Token
)

type Token struct {
  Key string
  user *users.User
  idstr string
  timeout time.Time     // Time at which token is no longer valid if not refreshed
  expiry time.Time      // Time past which token can not be auto-refreshed
}

func initTokens() {
  tokens = make(map[string]*Token)
}

func newToken(user *users.User, idstr string, timeoutDuration, expiryDuration time.Duration) *Token {
  if timeoutDuration == 0 {
    timeoutDuration = defaultTokenTimeoutDuration
  }
  if expiryDuration == 0 {
    expiryDuration = defaultTokenExpiryDuration
  }
  token := &Token{
    user: user,
    idstr: idstr,
    timeout: timeNow().Add(timeoutDuration),
    expiry: timeNow().Add(expiryDuration),
  }
  keynum := rand.Intn(1000000)
  token.Key = fmt.Sprintf("%06d", keynum)
  tokens[token.Key] = token
  return token
}

func currentToken(tokenKey, idstr string) (*Token, bool) {
  token := tokens[tokenKey]
  if token == nil {
    return nil, false
  }
  return token, token.isValid(idstr)
}

func (t *Token) isValid(idstr string) bool {
  if t.idstr != idstr {
    return false
  }
  if timeNow().After(t.timeout) {
    return false
  }
  return true
}

// updateTimeout resets the token timeout to be the timeout-duration
// from now, or the token expiry, whichever comes first.
func (t *Token) updateTimeout(timeoutDuration time.Duration) {
  if timeoutDuration == 0 {
    timeoutDuration = defaultTokenTimeoutDuration
  }
  timeout := timeNow().Add(timeoutDuration)
  if timeout.After(t.expiry) {
    timeout = t.expiry
  }
  t.timeout = timeout
}

func (t *Token) User() *users.User {
  return t.user
}

// cookie creates the HttpOnly cookie that contains our authentication key.
func (t *Token) cookie(tokenCookieName string) *http.Cookie {
  return &http.Cookie{
    Name: tokenCookieName,
    Path: "/",
    Value: t.Key,
    Expires: t.timeout,
    HttpOnly: true,
  }
}

// timeoutCookie creates a cookie, readable by the client javascript code,
// with a value that is the truncated number of seconds until our cookies expire.
func (t *Token) timeoutCookie(tokenCookieName string) *http.Cookie {
  return &http.Cookie{
    Name: tokenCookieName + "_TIMEOUT",
    Path: "/",
    Value: strconv.Itoa(int(t.timeout.Sub(time.Now()).Seconds())),
    Expires: t.timeout,
  }
}
