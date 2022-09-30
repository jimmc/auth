package users

import (
  "log"

  "github.com/jimmc/auth/permissions"
)

type Users struct {
  records [][]string
  users map[string]*User
}

func NewUsers(records [][]string, users map[string]*User) *Users {
  return &Users{
    records: records,
    users: users,
  }
}

func Empty() *Users {
  return &Users{
    records: make([][]string, 0),
    users: make(map[string]*User),
  }
}

func (m *Users) UserCount() int {
  return len(m.records)
}

func (m *Users) Records() [][]string {
  return m.records
}

func (m *Users) AddUser(userid, cryptword string, perms *permissions.Permissions) {
  m.addUserOnly(userid, cryptword, perms)
  m.addRecord(userid, cryptword, perms.ToString())
}

func (m *Users) addUserOnly(userid, cryptword string, perms *permissions.Permissions) {
  user := &User{
    userid: userid,
    cryptword: cryptword,
    perms: perms,
  }
  m.users[userid] = user
}

func (m *Users) addRecord(userid, cryptword string, perms string) {
  for r, record := range m.records {
    if record[0] == userid {
      // This user already exists, update the existing record
      m.records[r][1] = cryptword
      if len(m.records[r]) < 3 {
        m.records[r] = append(m.records[r], perms)
      } else {
        m.records[r][2] = perms
      }
      return
    }
  }
  record := []string{userid, cryptword, perms}
  m.records = append(m.records, record)
}

func (m *Users) User(userid string) *User {
  return m.users[userid]
}

func (m *Users) SetCryptword(userid, cryptword string) {
  for r, record := range(m.records) {
    if record[0] == userid {
      m.records[r][1] = cryptword
      user := m.User(userid)
      if user == nil {  // should never happen
        log.Printf("Error setting cryptword, user %s is in records but not users", userid)
        return
      }
      user.SetCryptword(cryptword)
      return
    }
  }
  // Didn't find the record, add a new one
  record := []string{userid, cryptword, ""}
  m.records = append(m.records, record)
  m.AddUser(userid, cryptword, permissions.FromString(""))
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
