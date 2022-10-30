// The auth package implements a simple password mechanism to allow
// authentication of API calls.
// We start with the username and password as the user entered it.
// From those two we generate the hashword by passing those two
// through sha256. This is so we don't have to send the password
// over the wire in plaintext, although it doesn't provide any
// real security, since an attacker who gets the hashword can just
// send it directly rather than producing it from the password.
// The server looks up the username in its database and retrieves
// the aaltword, in which the first some characters are the salt.
// That salt is composed with the hashword and passed through
// sha256, and the result is compared to the remainder of the saltword.
// If they match, the user is authenticated.

package auth

import (
  "crypto/rand"
  "crypto/sha256"
  "encoding/hex"
  "fmt"
  "net/http"
  "strings"
  "syscall"

  "github.com/golang/glog"
  "golang.org/x/crypto/ssh/terminal"

  "github.com/jimmc/auth/store"
)

type Config struct {
  Prefix string                 // The prefix string used for our API calls
  Store store.Store             // The storage module to load and save our data.
  TokenCookieName string        // The name of the cookie we use to store our auth data.
}

type Handler struct {
  ApiHandler http.Handler
  config *Config
}

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
// and the given password, with a randomly generated salt..
func (h *Handler) UpdatePassword(username, password string) error {
  err := h.loadUsers()
  if err != nil {
    return err
  }
  hashword := h.generateHashword(username, password)
  salt, err := h.generateSalt()
  if err != nil {
    return err
  }
  saltword := h.generateSaltword(salt, hashword)
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
  actualSaltword := h.getSaltword(username)
  salt := h.getSaltFromSaltword(actualSaltword)
  proposedSaltword := h.generateSaltword(salt, hashword)
  glog.V(4).Infof("actualSaltword=%q", actualSaltword)
  glog.V(4).Infof("proposedSaltword=%q", proposedSaltword)
  return proposedSaltword == actualSaltword
}

func (h *Handler) generateSalt() (string, error) {
  c := 8
  b := make([]byte, c)
  _, err := rand.Read(b)
  if err != nil {
    return "", err
  }
  salt, err := hex.EncodeToString(b), nil
  glog.V(4).Infof("New salt=%s", salt)
  return salt, err
}

func (h *Handler) getSaltFromSaltword(saltword string) string {
  i := strings.Index(saltword, "/")
  if i<0 {
    return ""           // No salt found
  }
  return saltword[:i]
}

func (h *Handler) generateSaltword(salt, hashword string) string {
  return salt + "/" + sha256sum(salt + "/" + hashword)
}

func sha256sum(s string) string {
  sum := sha256.Sum256([]byte(s))
  return fmt.Sprintf("%x", sum)
}
