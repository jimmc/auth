package store

import (
  "database/sql"
  "os"
  "testing"

  _ "github.com/mattn/go-sqlite3"

  //"github.com/jimmc/auth/permissions"
  "github.com/jimmc/auth/users"
)

// const CanDoSomething permissions.Permission = "something"

func TestCreatePasswordTable(t *testing.T) {
  dbtype := "sqlite3"
  dbloc := "/tmp/xxx.db"
  os.Remove(dbloc)
  defer os.Remove(dbloc)
  db, err := sql.Open(dbtype, dbloc)
  if err != nil {
    t.Fatalf("error opening sql database: %v", err)
  }
  pdb := NewPwDB(db)
  uu, _ := pdb.Load()    // No-op, just for coverage.
  err = pdb.CreatePasswordTable()
  if err != nil {
    t.Fatalf("error creating password table: %v", err)
  }
  pdb.Save(uu)    // No-op, just for coverage.
}

func TestDbUpdateUser(t *testing.T) {
  dbtype := "sqlite3"
  dbloc := "/tmp/xxx.db"
  os.Remove(dbloc)
  defer os.Remove(dbloc)
  db, err := sql.Open(dbtype, dbloc)
  if err != nil {
    t.Fatalf("error opening sql database: %v", err)
  }
  pdb := NewPwDB(db)
  err = pdb.CreatePasswordTable()
  if err != nil {
    t.Fatalf("error creating password table: %v", err)
  }
  if got, want := pdb.UserCount(), 0; got != want {
    t.Errorf("user count before mods: got %d, want %d", got, want)
  }
  var nilUser *users.User
  if got, want := pdb.User("user1"), nilUser; got != want {
    t.Errorf("user1 before being created: got %v, want %v", got, want)
  }
  // user1 does not exist; first call to SetCryptword creates it.
  pdb.SetCryptword("user1", "cw1")
  if got, want := pdb.UserCount(), 1; got != want {
    t.Errorf("user count after adding user1: got %d, want %d", got, want)
  }
  u1 := pdb.User("user1")
  if u1 == nil {
    t.Fatalf("expected user1, got nil")
  }
  if got, want := u1.Cryptword(), "cw1"; got != want {
    t.Errorf("user1 Cryptword after being added: got %v, want %v", got, want)
  }
  // user1 exists, so this call to SetCryptword updates it.
  pdb.SetCryptword("user1", "cw1b")
  u1 = pdb.User("user1")       // Get the user again after making this change.
  if u1 == nil {
    t.Fatalf("expected user1, got nil")
  }
  if got, want := u1.Cryptword(), "cw1b"; got != want {
    t.Errorf("user1 Cryptword after being updated: got %v, want %v", got, want)
  }
}
