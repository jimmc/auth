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
// where the permissions field is a comma-separated list of permissions names.
type PwFile struct {
    Filename string     // The CSV file with our data.
}

func NewPwFile(filename string) *PwFile {
  return &PwFile{
    Filename: filename,
  }
}

func (pf *PwFile) CreatePasswordFile() error {
  f, err := os.Open(pf.Filename)
  if err == nil || !os.IsNotExist(err) {
    return fmt.Errorf("password file already exists at %s", pf.Filename)
  }
  f, err = os.Create(pf.Filename)
  if err != nil {
    return fmt.Errorf("error creating new password file at %s: %v", pf.Filename, err)
  }
  f.Close()
  return nil
}

func (pf *PwFile) Load() (*users.Users, error) {
  f, err := os.Open(pf.Filename)
  if err != nil {
    return nil, fmt.Errorf("error opening password file %s: %v", pf.Filename, err)
  }
  r := csv.NewReader(bufio.NewReader(f))

  records, err := r.ReadAll()
  if err != nil {
    return nil, fmt.Errorf("error loading password file %s: %v", pf.Filename, err)
  }

  uu := pf.recordsToUsers(records)
  return users.NewUsers(records, uu), nil
}

func (pf *PwFile) recordsToUsers(records [][]string) map[string]*users.User {
  uu := make(map[string]*users.User)
  for _, record := range records {
    userid := record[0]
    cryptword := record[1]
    var perms *permissions.Permissions
    if len(record) > 2 {
      perms = permissions.FromString(record[2])
    }
    user := users.NewUser(userid, cryptword, perms)
    uu[userid] = user
  }
  return uu
}

func (pf *PwFile) Save(uu *users.Users) error {
  newFilePath := pf.Filename + ".new"
  f, err := os.Create(newFilePath)
  if err != nil {
    return fmt.Errorf("error creating new password file %s: %v", newFilePath, err)
  }
  w := csv.NewWriter(bufio.NewWriter(f))
  err = w.WriteAll(uu.Records())
  if err != nil {
    return fmt.Errorf("error writing new password file %s: %v", newFilePath, err)
  }
  w.Flush()
  f.Close()

  backupFilePath := pf.Filename + "~"
  err = os.Rename(pf.Filename, backupFilePath)
  if err != nil {
    return fmt.Errorf("error moving old file to backup path %s: %v", backupFilePath, err)
  }
  err = os.Rename(newFilePath, pf.Filename)
  if err != nil {
    return fmt.Errorf("error moving new file %s to become active file: %v", newFilePath, err)
  }

  return nil
}
