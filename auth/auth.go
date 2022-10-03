// The auth package implements a simple password mechanism to allow
// authentication of API calls.
// We use a database that stores two pieces of data for each user:
// a userid and a cryptword. The cryptword is generated by concatenating
// the userid with the user's password and taking a sha256sum of that.
// For login, the user enters a userid and a password into the client,
// which generates the cryptword. It then gets the current time in seconds
// since the epoch, converts that number to a decimal string, concatenates
// the cryptword with that string, and takes the sha256sum of that, which it
// sends to the server along with the username.

package auth

import (
  "crypto/sha256"
  "fmt"
  "net/http"
  "strconv"
  "syscall"
  "time"

  "github.com/golang/glog"
  "golang.org/x/crypto/ssh/terminal"

  "github.com/jimmc/auth/store"
)

var (
  timeNow = time.Now            // Allow overriding for unit testing.
)

type Config struct {
  Prefix string                 // The prefix string used for our API calls
  Store store.Store             // The storage module to load and save our data.
  TokenCookieName string        // The name of the cookie we use to store our auth data.
  MaxClockSkewSeconds int
}

type Handler struct {
  ApiHandler http.Handler
  config *Config
}

func NewHandler(c *Config) Handler {
  h := Handler{config: c}
  if c.Store==nil {
    glog.Errorf("Error: no Store provided")
    return h
  }
  err := h.loadUsers()
  if err != nil {
    glog.Errorf("Error loading password file: %v", err)
  }
  h.initApiHandler()
  initTokens()
  return h
}

// Read a password from the terminal and pass it to UpdatePassword.
// This function is difficult to test automatically. It should be tested manually.
func (h *Handler) UpdateUserPassword(userid string) error {
  if !terminal.IsTerminal(syscall.Stdin) {
    return fmt.Errorf("updatePassword option requires terminal for input")
  }
  fmt.Printf("New password: ")
  pw, err := terminal.ReadPassword(syscall.Stdin)
  fmt.Printf("\n")
  if err != nil {
    return fmt.Errorf("Error reading new password: %v", err)
  }
  fmt.Printf("Repeat new password: ")
  pw2, err := terminal.ReadPassword(syscall.Stdin)
  fmt.Printf("\n")
  if err != nil {
    return fmt.Errorf("Error reading new password: %v", err)
  }
  if string(pw2) != string(pw) {
    return fmt.Errorf("Passwords did not match")
  }
  return h.UpdatePassword(userid, string(pw))
}

// Set a password for a user into our password database. We don't save the
// plaintext password, we concatenate the userid with the raw password, take
// the sha256sum of that, and store that in our database.
func (h *Handler) UpdatePassword(userid, password string) error {
  err := h.loadUsers()
  if err != nil {
    return err
  }
  cryptword := h.generateCryptword(userid, password)
  h.setCryptword(userid, cryptword)
  err = h.saveUsers()
  if err != nil {
    return err
  }
  return nil
}

func (h *Handler) loadUsers() error {
  return h.config.Store.Load()
}

func (h *Handler) saveUsers() error {
  return h.config.Store.Save()
}

func (h *Handler) setCryptword(userid, cryptword string) {
  h.config.Store.SetCryptword(userid, cryptword)
}

// Get the encrypted password for the given user from our previously-loaded password file.
func (h *Handler) getCryptword(userid string) string {
  user :=  h.config.Store.User(userid)
  if user == nil {
    return ""
  }
  return user.Cryptword()
}

func (h *Handler) generateCryptword(userid, password string) string {
  return sha256sum(userid + "-" + password)
}

func (h *Handler) generateNonceAtTime(userid string, secondsSinceEpoch int64) string {
  cryptword := h.getCryptword(userid)
  shaInput := cryptword + "-" + strconv.FormatInt(secondsSinceEpoch, 10)
  return sha256sum(shaInput)
}

func (h *Handler) nonceIsValidAtTime(userid, nonce string, secondsSinceEpoch int64) bool {
  goodNonce := h.generateNonceAtTime(userid, secondsSinceEpoch)
  if nonce == goodNonce {
    return true
  } else {
    glog.Warningf("nonce %v does not match goodNonce %v", nonce, goodNonce)
    return false
  }
}

func (h *Handler) nonceIsValidNow(userid, nonce string, seconds int64) bool {
  t := timeNow().Unix()
  delta := t - seconds
  if delta > int64(h.config.MaxClockSkewSeconds) || delta < -int64(h.config.MaxClockSkewSeconds) {
    glog.Warningf("now=%v, client-time=%v, skew is more than max of %v",
        t, seconds, h.config.MaxClockSkewSeconds)
    return false
  }
  return h.nonceIsValidAtTime(userid, nonce, seconds)
}

func sha256sum(s string) string {
  sum := sha256.Sum256([]byte(s))
  return fmt.Sprintf("%x", sum)
}
