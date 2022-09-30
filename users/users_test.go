package users

import (
  "testing"

  "github.com/jimmc/auth/permissions"
)

const CanDoSomething permissions.Permission = "something"

func TestEmpty(t *testing.T) {
  m := Empty();
  if got, want := m.UserCount(), 0; got != want {
    t.Errorf("user count for initial Empty: got %d, want %d", got, want)
  }
  emptyPerms := permissions.FromString("")
  m.AddUser("user1", "crypt1", emptyPerms)
  if got, want := m.UserCount(), 1; got != want {
    t.Errorf("user count after adding a user: got %d, want %d", got, want)
  }
}
