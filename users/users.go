package users

import (
  "sort"

  "github.com/jimmc/auth/permissions"
)

type Users struct {
  users map[string]*User
}

func NewUsers(users map[string]*User) *Users {
  return &Users{
    users: users,
  }
}

func Empty() *Users {
  return NewUsers(make(map[string]*User))
}

func (m *Users) UserCount() int {
  return len(m.users)
}

// ToArray returns an array of *User sorted by userid.
func (m *Users) ToArray() []*User {
  count := m.UserCount()
  ua := make([]*User, count, count)
  n := 0
  for _, v := range m.users {
    ua[n] = v
    n++
  }
  sort.Sort(byUserId(ua))
  return ua
}

func (m *Users) AddUser(userid, cryptword string, perms *permissions.Permissions) {
  user := &User{
    userid: userid,
    cryptword: cryptword,
    perms: perms,
  }
  m.users[userid] = user
}

func (m *Users) User(userid string) *User {
  return m.users[userid]
}

func (m *Users) SetCryptword(userid, cryptword string) {
  user := m.User(userid)
  if user == nil {
    m.AddUser(userid, cryptword, permissions.FromString(""))
  } else {
    user.SetCryptword(cryptword)
  }
}

func (m *Users) Cryptword(userid string) string {
  user := m.User(userid)
  if user == nil {
    return ""
  }
  return user.Cryptword()
}

func (m *Users) HasPermission(userid string, perm permissions.Permission) bool {
  user := m.User(userid)
  if user == nil {
    return false
  }
  return user.HasPermission(perm)
}

// The byUserId type allows us to use sort.Sort to sort an array of *User.
type byUserId []*User
func (ua byUserId) Len() int {
  return len(ua)
}
func (ua byUserId) Swap(i, j int) {
  ua[i], ua[j] = ua[j], ua[i]
}
func (ua byUserId) Less(i, j int) bool {
  return ua[i].userid < ua[j].userid
}
