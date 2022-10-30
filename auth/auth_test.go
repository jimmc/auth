package auth

import (
  "io/ioutil"
  "os"
  "testing"

  "github.com/jimmc/auth/store"
)

// Returns a config and the temp file used in the config
func makeTestConfig(t *testing.T) (*Config, *os.File) {
  t.Helper()
  pf, err := ioutil.TempFile("", "auth-test")
  if err != nil {
    t.Fatalf("failed to create temp password file")
  }
  pwStore := store.NewPwFile(pf.Name())
  c := &Config{
    Prefix: "/pre/",
    Store: pwStore,
  }
  return c, pf
}

func TestConfigNoStore(t *testing.T) {
  c := &Config{
    Prefix: "/abc/",
  }
  h := NewHandler(c)
  if h==nil {
    t.Error("Expected handler even when no Store in config, got nil")
  }
}

// Try calling UpdateUserPassword, we expect an error because it
// wants to use stdin.
func TestUpdateUserPassword(t *testing.T) {
  testConfig, pf := makeTestConfig(t)
  defer os.Remove(pf.Name())    // clean up
  h := NewHandler(testConfig)
  err := h.UpdateUserPassword("no-such-user")
  if err == nil {
    t.Errorf("Exepcted error from UpdateUserPassword, got nil")
  }
}

func TestPasswordFile(t *testing.T) {
  testConfig, pf := makeTestConfig(t)
  defer os.Remove(pf.Name())    // clean up
  h := NewHandler(testConfig)
  err := h.loadUsers()
  if err != nil {
    t.Errorf("failed to load empty password file")
  }
  if got, want := h.config.Store.UserCount(), 0; got != want {
    t.Errorf("empty tmp password file got %d records, want %d", got, want)
  }
  err = pf.Close()
  if err != nil {
    t.Errorf("error closing tmp password file")
  }

  pwStore := (testConfig.Store).(*store.PwFile)
  err = pwStore.CreatePasswordFile()
  if err == nil {
    t.Errorf("attempting to create existing password file should fail")
  }
  err = os.Remove(pf.Name())
  if err != nil {
    t.Errorf("failed to remove tmp password file: %v", err)
  }
  err = pwStore.CreatePasswordFile()
  if err != nil {
    t.Errorf("failed to create password file")
  }

  sw := h.getSaltword("user1")
  if sw != "" {
    t.Errorf("user1 should have no saltword before being set")
  }
  err = h.UpdatePassword("user1", "abcd")
  if err != nil {
    t.Errorf("failed to update password: %v", err)
  }
  err = h.loadUsers()
  if err != nil {
    t.Errorf("failed to load password file after updating: %v", err)
  }
  sw = h.getSaltword("user1")
  if sw == "" {
    t.Errorf("user1 should have saltword after being set")
  }
  salt := h.getSaltFromSaltword(sw)
  if salt == "" {
    t.Errorf("Blank salt after setting saltword")
  }
  hashword := h.generateHashword("user1", "abcd")
  wantsw := h.generateSaltword(salt, hashword)
  if got, want := sw, wantsw; got!=want {
    t.Errorf("user saltword after saving: got %s, want %s", got, want)
  }

  // Saving the password file after a change is done by creating a new temp
  // file and moving it onto the old file. To make this fail, we create a
  // file of that new name and make it read-only.
  // Now make the password file protected so a write on save fails
  tfName := pf.Name()+".new"
  tf, err := os.Create(tfName)
  if err != nil {
    t.Fatalf("failed to create temp password file")
  }
  defer os.Remove(tf.Name())    // clean up
  err = os.Chmod(tf.Name(), 0400)       // read-only
  if err!=nil {
    t.Fatalf("error setting temp password file (~) to read-only: %v", err)
  }
  err = h.UpdatePassword("user1", "xyz")
  if err == nil {
    t.Errorf("expected error updating password, did not get error")
  }
}

func TestMissingPasswordFile(t *testing.T) {
  noSuchFile := "/no/such/file/foo.txt"
  pwStore := store.NewPwFile(noSuchFile)
  c := &Config{
    Prefix: "/pre/",
    Store: pwStore,
  }
  h := NewHandler(c)
  err := h.loadUsers()
  if err == nil {
    t.Errorf("expected error loading file, did not get error")
  }
  err = h.UpdatePassword("user1", "abcd")
  if err == nil {
    t.Errorf("expected error updating password, did not get error")
  }
}

func TestHashing(t *testing.T) {
  testConfig, pf := makeTestConfig(t)
  defer os.Remove(pf.Name())    // clean up
  h := NewHandler(testConfig)

  salt, err := h.generateSalt()
  if err != nil {
    t.Errorf("generateSalt returned error: %v", err)
  } else if got, want := len(salt), 16; got!=want {
    t.Errorf("salt length: got %d, want %d", got, want)
  }

  if got, want := h.generateHashword("a", "b"), "c14cddc033f64b9dea80ea675cf280a015e672516090a5626781153dc68fea11"; got!=want {
    t.Errorf("hashword: got %s, want %s", got, want)
  }

  if got, want := h.generateSaltword("abc", "def"), "abc/3c56f20931870aab85951364886aef949368f5f12d572ea95f5ca96a280944e6"; got!=want {
    t.Errorf("saltword: got %s, want %s", got, want)
  }

  if got, want := h.getSaltFromSaltword("abc/def"), "abc"; got!=want {
    t.Errorf("getSaltFromSaltword: got %s, want %s", got, want)
  }
  if got, want := h.getSaltFromSaltword("abcdef"), ""; got!=want {
    t.Errorf("getSaltFromSaltword with no separator: got %s, want empty string", got)
  }
}

func TestSaltword(t *testing.T) {
  testConfig, pf := makeTestConfig(t)
  defer os.Remove(pf.Name())    // clean up
  h := NewHandler(testConfig)
  cw := h.getSaltword("user1")
  if cw != "" {
    t.Errorf("saltword for unknown user should be blank")
  }
  h.setSaltword("user1", "abcdef")
  cw = h.getSaltword("user1")
  if cw != "abcdef" {
    t.Errorf("saltword should be equal to what was previously set")
  }
  h.setSaltword("user1", "ghi")
  cw = h.getSaltword("user1")
  if cw != "ghi" {
    t.Errorf("saltword should be equal to new value")
  }
}

func TestSha256sum(t *testing.T) {
  input := "abc-def"
  want := "abe70a7e804fcd4069cdee57873899c152b2f1eace1f2fd89b1a6e9b862481b9"
  if got := sha256sum(input); got != want {
    t.Errorf("sha256sum got %s want %s", got, want)
  }
}
