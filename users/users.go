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

// ToArray returns an array of *User sorted by username.
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

func (m *Users) AddUser(username, saltword string, perms *permissions.Permissions) {
  user := &User{
    username: username,
    saltword: saltword,
    perms: perms,
  }
  m.users[username] = user
}

func (m *Users) User(username string) *User {
  return m.users[username]
}

func (m *Users) SetSaltword(username, saltword string) {
  user := m.User(username)
  if user == nil {
    m.AddUser(username, saltword, permissions.FromString(""))
  } else {
    user.SetSaltword(saltword)
  }
}

func (m *Users) Saltword(username string) string {
  user := m.User(username)
  if user == nil {
    return ""
  }
  return user.Saltword()
}

func (m *Users) HasPermission(username string, perm permissions.Permission) bool {
  user := m.User(username)
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
  return ua[i].username < ua[j].username
}
