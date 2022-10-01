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

func TestUserData(t *testing.T) {
  u1 := NewUser("user1", "foo", nil)
  if got, want := u1.HasPermission(CanDoSomething), false; got != want {
    t.Errorf("wrong permission: got %v, want %v", got, want)
  }
  if got, want := u1.PermissionsString(), ""; got != want {
    t.Errorf("wrong permissions string for user1: got %q, want %q", got, want)
  }
  u2 := NewUser("user2", "bar", permissions.FromString("something"))
  if got, want := u2.PermissionsString(), "something"; got != want {
    t.Errorf("wrong permissions string for user2: got %q, want %q", got, want)
  }
  u0 := NewUser("user0", "foo", nil)
  um := make(map[string]*User, 0)
  um[u1.Id()] = u1
  um[u2.Id()] = u2
  um[u0.Id()] = u0
  uu := NewUsers(um)
  if got, want := uu.UserCount(), 3; got != want {
    t.Errorf("wrong user count: got %d, want %d", got, want)
  }
  ua := uu.ToArray()
  if got, want := len(ua), 3; got != want {
    t.Errorf("wrong array length: got %d, want %d", got, want)
  }
  if got, want := ua[1].Id(), "user1"; got != want {
    t.Errorf("wrong user at ua[0]: got %q, want %q", got, want)
  }
  if got, want := uu.User("user2"), u2; got != want {
    t.Errorf("wrong user at uu[user2]: got %v, want %v", got, want)
  }
  if got, want := uu.HasPermission("user2", CanDoSomething), true; got != want {
    t.Errorf("wrong permission for user2: got %v, want %v", got, want)
  }
  if got, want := uu.HasPermission("user3", CanDoSomething), false; got != want {
    t.Errorf("wrong permission for user3: got %v, want %v", got, want)
  }

  if got, want := uu.Cryptword("user1"), "foo"; got != want {
    t.Errorf("wrong cryptword for user1: got %q, want %q", got, want)
  }
  uu.SetCryptword("user1", "xxx")
  if got, want := uu.Cryptword("user1"), "xxx"; got != want {
    t.Errorf("wrong updated cryptword for user1: got %q, want %q", got, want)
  }

  if got, want := uu.Cryptword("user3"), ""; got != want {
    t.Errorf("wrong cryptword for user3: got %q, want %q", got, want)
  }
  uu.SetCryptword("user3", "yyy")
  if got, want := uu.Cryptword("user3"), "yyy"; got != want {
    t.Errorf("wrong updated cryptword for user3: got %q, want %q", got, want)
  }
}
