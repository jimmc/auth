package store

import (
  "bufio"
  "encoding/csv"
  "fmt"
  "os"

  "github.com/jimmc/auth/permissions"
  "github.com/jimmc/auth/users"
)

// PwFile implements the Store interface to load and store data in a file
// similar to a Unix /etc/passwd file.
// Each line has data for one user in colon-separated fields with the format
//   username:password:permissions
// where the permissions field is a comma-separated list of permission names.
type PwFile struct {
    filename string     // The CSV file with our data.
    users *users.Users
}

func NewPwFile(filename string) *PwFile {
  return &PwFile{
    filename: filename,
    users: users.Empty(),
  }
}

func (pf *PwFile) CreatePasswordFile() error {
  f, err := os.Open(pf.filename)
  if err == nil || !os.IsNotExist(err) {
    return fmt.Errorf("password file already exists at %s", pf.filename)
  }
  f, err = os.Create(pf.filename)
  if err != nil {
    return fmt.Errorf("error creating new password file at %s: %v", pf.filename, err)
  }
  f.Close()
  return nil
}

func (pf *PwFile) Load() error {
  f, err := os.Open(pf.filename)
  if err != nil {
    return fmt.Errorf("error opening password file %s: %v", pf.filename, err)
  }
  r := csv.NewReader(bufio.NewReader(f))
  r.FieldsPerRecord = 3         // username, password, permissions

  records, err := r.ReadAll()
  if err != nil {
    return fmt.Errorf("error loading password file %s: %v", pf.filename, err)
  }

  uu := pf.recordsToUsers(records)
  pf.users = users.NewUsers(uu)
  return nil
}

func (pf *PwFile) Save() error {
  newFilePath := pf.filename + ".new"
  f, err := os.Create(newFilePath)
  if err != nil {
    return fmt.Errorf("error creating new password file %s: %v", newFilePath, err)
  }
  w := csv.NewWriter(bufio.NewWriter(f))
  err = w.WriteAll(pf.usersToRecords(pf.users))
  if err != nil {
    return fmt.Errorf("error writing new password file %s: %v", newFilePath, err)
  }
  w.Flush()
  f.Close()

  backupFilePath := pf.filename + "~"
  err = os.Rename(pf.filename, backupFilePath)
  if err != nil {
    return fmt.Errorf("error moving old file to backup path %s: %v", backupFilePath, err)
  }
  err = os.Rename(newFilePath, pf.filename)
  if err != nil {
    return fmt.Errorf("error moving new file %s to become active file: %v", newFilePath, err)
  }

  return nil
}

func (pf *PwFile) recordsToUsers(records [][]string) map[string]*users.User {
  uu := make(map[string]*users.User)
  for _, record := range records {
    username := record[0]
    saltword := record[1]
    perms := permissions.FromString(record[2])
    user := users.NewUser(username, saltword, perms)
    uu[username] = user
  }
  return uu
}

func (pf *PwFile) usersToRecords(uu *users.Users) [][]string {
  count := uu.UserCount()
  records := make([][]string, count, count)
  ua := uu.ToArray()
  for n, u := range ua {
    records[n] = []string{ u.Id(), u.Saltword(), u.PermissionsString() }
  }
  return records
}

func (pf *PwFile) User(username string) *users.User {
  return pf.users.User(username)
}

func (pf *PwFile) SetSaltword(username, saltword string) {
  pf.users.SetSaltword(username, saltword)
}

func (pf *PwFile) UserCount() int {
  return pf.users.UserCount()
}
