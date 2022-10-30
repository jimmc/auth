package store

import (
  "bytes"
  "io/ioutil"
  "os"
  "testing"

  "github.com/jimmc/auth/permissions"
  "github.com/jimmc/auth/users"
)

const CanDoSomething permissions.Permission = "something"

func TestCreatePasswordFile(t *testing.T) {
  pf, err := ioutil.TempFile("", "pwfile-test")
  if err != nil {
    t.Fatalf("failed to create temp password file")
  }
  defer os.Remove(pf.Name())    // clean up
  err = pf.Close()
  if err != nil {
    t.Errorf("error closing tmp password file")
  }

  pwStore := NewPwFile(pf.Name())
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
}

func TestBadCreatePasswordFile(t *testing.T) {
  pwStore := NewPwFile("/no/such/file/foo.txt")
  err := pwStore.CreatePasswordFile()
  if err == nil {
    t.Errorf("attempting to create password file in bad location should fail")
  }
}

func TestLoadBadPasswordFile(t *testing.T) {
  pwStore := NewPwFile("/no/such/file/foo.txt")
  err := pwStore.Load()
  if err == nil {
    t.Errorf("attempting to load password file from bad location should fail")
  }
}

func TestUpdateUser(t *testing.T) {
  pf, err := ioutil.TempFile("", "pwfile-test")
  if err != nil {
    t.Fatalf("failed to create temp password file")
  }
  defer os.Remove(pf.Name())    // clean up
  err = pf.Close()
  if err != nil {
    t.Errorf("error closing tmp password file")
  }

  pwStore := NewPwFile(pf.Name())
  if got, want := pwStore.UserCount(), 0; got != want {
    t.Errorf("user count before mods: got %d, want %d", got, want)
  }
  var nilUser *users.User
  if got, want := pwStore.User("user1"), nilUser; got != want {
    t.Errorf("user1 before being created: got %v, want %v", got, want)
  }
  pwStore.SetSaltword("user1", "cw1")
  if got, want := pwStore.UserCount(), 1; got != want {
    t.Errorf("user count after adding user1: got %d, want %d", got, want)
  }
  if got, want := pwStore.User("user1").Saltword(), "cw1"; got != want {
    t.Errorf("user1 Saltword after being added: got %v, want %v", got, want)
  }
}

func TestSaveError(t *testing.T) {
  pf, err := ioutil.TempFile("", "pwfile-test")
  if err != nil {
    t.Fatalf("failed to create temp password file")
  }
  defer os.Remove(pf.Name())    // clean up
  err = pf.Close()
  if err != nil {
    t.Errorf("error closing tmp password file")
  }
  pw := NewPwFile(pf.Name())
  err = pw.Load()
  if err != nil {
    t.Errorf("error loading password file: %v", err)
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
  err = pw.Save()
  if err == nil {
    t.Errorf("expected error updating password, did not get error")
  }
}

func TestLoadSaveFile(t *testing.T) {
  pwfile := "testdata/pw1.txt"
  pw := NewPwFile(pwfile)
  err := pw.Load()
  if err != nil {
    t.Fatalf("failed to load password file %s: %v", pwfile, err)
  }

  if got, want := pw.UserCount(), 2; got != want {
    t.Fatalf("user count in password file %s: got %d, want %d", pwfile, got, want)
  }
  if got, want := pw.User("user1").Saltword(), "d761bfe5ffda189a8f1c2212c5fb3fe65274a070d0b1c4f4ec6c2c020db5f22b";
      got != want {
    t.Errorf("cryptword for user1: got %s, want %s", got, want)
  }

  perms := permissions.FromString("something")
  pw.users.AddUser("user3", "cw3", perms)
  pw.users.SetSaltword("user2", "cw2")

  if got, want := pw.users.HasPermission("user3", CanDoSomething), true; got !=want {
    t.Errorf("something permission for user3: got %v, want %v", got, want)
  }
  if got, want := pw.users.HasPermission("user2", CanDoSomething), false; got !=want {
    t.Errorf("something permission for user2: got %v, want %v", got, want)
  }

  pwsavefile := "testdata/tmp-pw-save.txt"
  pwsavebakfile := "testdata/tmp-pw-save.txt~"
  os.Remove(pwsavefile)
  defer os.Remove(pwsavefile)
  defer os.Remove(pwsavebakfile)
  // Pre-create the old file to be moved when the new is saved
  oldContents := []byte("old pw file")
  err = ioutil.WriteFile(pwsavefile, oldContents, 0644)
  if err != nil {
    t.Fatalf("failed to precreate saved password file %s: %v:", pwsavefile, err)
  }
  pw2 := NewPwFile(pwsavefile)
  pw2.users = pw.users          // Hack: make pw2 write the user data of pw1
  err = pw2.Save()
  if err != nil {
    t.Fatalf("error saving new password file %s: %v", pwsavefile, err)
  }

  // Make sure we renamed the old file as a backup
  pwgot, err := ioutil.ReadFile(pwsavebakfile)
  if err != nil {
    t.Errorf("failed to load save-backup password file %s: %v", pwsavebakfile, err)
  }
  if !bytes.Equal(pwgot, oldContents) {
    t.Errorf("save password file contents: got %s, want %s", pwgot, oldContents)
  }

  // Make sure the new password file is correct
  pwgolden := "testdata/pw2-golden.txt"
  pwgot, err = ioutil.ReadFile(pwsavefile)
  if err != nil {
    t.Fatalf("Failed to read saved password file %s: %v", pwsavefile, err)
  }
  pwwant, err := ioutil.ReadFile(pwgolden)
  if err != nil {
    t.Fatalf("Failed to read reference password file %s: %v", pwgolden, err)
  }
  if !bytes.Equal(pwgot, pwwant) {
    t.Errorf("password file contents don't match, got '%s', want '%s'", pwgot, pwwant)
  }
}
