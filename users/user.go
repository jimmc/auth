package users

import (
  "github.com/jimmc/auth/permissions"
)

type User struct {
  userid string
  cryptword string
  perms *permissions.Permissions
}

func NewUser(userid, cryptword string, perms *permissions.Permissions) *User {
  return &User{
    userid: userid,
    cryptword: cryptword,
    perms: perms,
  }
}

func (u *User) Cryptword() string {
  return u.cryptword
}

func (u *User) SetCryptword(cryptword string) {
  u.cryptword = cryptword
}

func (u *User) Id() string {
  return u.userid
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
