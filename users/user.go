package users

import (
  "github.com/jimmc/auth/permissions"
)

type User struct {
  username string
  saltword string
  perms *permissions.Permissions
}

func NewUser(username, saltword string, perms *permissions.Permissions) *User {
  return &User{
    username: username,
    saltword: saltword,
    perms: perms,
  }
}

func (u *User) Saltword() string {
  return u.saltword
}

func (u *User) SetSaltword(saltword string) {
  u.saltword = saltword
}

func (u *User) Id() string {
  return u.username
}

func (u *User) HasPermission(perm permissions.Permission) bool {
  if u.perms == nil {
    return false
  }
  return u.perms.HasPermission(perm)
}

func (u *User) PermissionsString() string {
  if u.perms == nil {
    return ""
  }
  return u.perms.ToString()
}
