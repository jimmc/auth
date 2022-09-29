package permissions

import (
  "testing"
)

const (
    CanDoSomething Permission = "something"
)

func TestFromString(t *testing.T) {
  p := FromString("")
  if got, want := len(p.perms), 0; got != want {
    t.Errorf("Number of permissions in empty string: got %d, want %d", got, want)
  }
  if p.HasPermission(CanDoSomething) {
    t.Errorf("empty string should not give CanDoSomething permission")
  }

  p = FromString("something")
  if got, want := len(p.perms), 1; got != want {
    t.Errorf("Number of permissions in 'something' string: got %d, want %d", got, want)
  }
  if !p.HasPermission(CanDoSomething) {
    t.Errorf("'something' string fails to give CanDoSomething permission")
  }
}
