// The auth package implements a simple password mechanism to allow
// authentication of API calls.
// We start with the username and password as the user entered it.
// From those two we generate the hashword by passing those two
// through sha256. This is so we don't have to send the password
// over the wire in plaintext, although it doesn't provide any
// real security, since an attacker who gets the hashword can just
// send it directly rather than producing it from the password.
// We pass that hashword through bcrypt, which adds a salt and
// hashes again, and we save that value as our saltword.
// During authentication, the client gets the password from the
// user and generates the hashword, which it sends to the server along
// with the username. The server looks up the username in its database
// and retrieves the saltword. The saltword and the hashword are passed
// to bcrypt's comparison function. If they match, the user is authenticated.

package auth

import (
  "crypto/sha256"
  "encoding/hex"
  "fmt"
  "net/http"
  "syscall"
  "time"

  "github.com/golang/glog"
  "golang.org/x/crypto/bcrypt"
  "golang.org/x/crypto/ssh/terminal"

  "github.com/jimmc/auth/store"
)

type Config struct {
  Prefix string                 // The prefix string used for our API calls
  Store store.Store             // The storage module to load and save our data.
  TokenCookieName string        // The name of the cookie we use to store our auth data.
  TokenTimeoutDuration time.Duration   // Amount of idle time until token times out.
  TokenExpiryDuration time.Duration    // Amount of time until hard expire of the token.

}

type Handler struct {
  ApiHandler http.Handler
  config *Config
}

const (
  defaultTokenTimeoutDuration = time.Duration(1) * time.Hour
  defaultTokenExpiryDuration = time.Duration(10) * time.Hour
)

const bcryptCost = 12   // The cost factor we pass to bcrypt.GenerateFromPassword.

func NewHandler(c *Config) *Handler {
  h := &Handler{config: c}
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
func (h *Handler) UpdateUserPassword(username string) error {
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
  return h.UpdatePassword(username, string(pw))
}

// Set the saltword for a user into our database based on the username
// and the given password, with a randomly generated salt.
func (h *Handler) UpdatePassword(username, password string) error {
  err := h.loadUsers()
  if err != nil {
    return err
  }
  hashword := h.generateHashword(username, password)
  saltword, err := h.generateSaltword(hashword)
  if err != nil {
    return err
  }
  h.setSaltword(username, saltword)
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

func (h *Handler) setSaltword(username, saltword string) {
  h.config.Store.SetSaltword(username, saltword)
}

// Get the saltword for the given user from our previously-loaded password file.
func (h *Handler) getSaltword(username string) string {
  user :=  h.config.Store.User(username)
  if user == nil {
    return ""
  }
  return user.Saltword()
}

func (h *Handler) generateHashword(username, password string) string {
  return sha256sum(username + "/" + password)
}

func (h *Handler) hashwordIsValid(username, hashword string) bool {
  saltword := h.getSaltword(username)
  saltwordBytes, err := hex.DecodeString(saltword)
  if err != nil {
    glog.V(4).Infof("error converting saltword to bytes: %v", err)
    return false
  }
  err = bcrypt.CompareHashAndPassword(saltwordBytes, []byte(hashword))
  if err != nil {
    glog.V(4).Infof("password compare failed: %v", err)
    return false
  }
  return true
}

func (h *Handler) generateSaltword(hashword string) (string, error) {
  // bcrypt adds random salt as includes that in the returned bytes.
  saltwordBytes, err :=  bcrypt.GenerateFromPassword([]byte(hashword), bcryptCost)
  if err != nil {
    return "", err
  }
  return hex.EncodeToString(saltwordBytes), nil
}

func sha256sum(s string) string {
  sum := sha256.Sum256([]byte(s))
  return fmt.Sprintf("%x", sum)
}
