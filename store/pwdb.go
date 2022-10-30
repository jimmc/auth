package store

import (
  "database/sql"

  "github.com/golang/glog"

  "github.com/jimmc/auth/permissions"
  "github.com/jimmc/auth/users"
)

// PwDB implements the Store interface to load and store data in an SQL database.
// Data is stored in a table called "user" with three string columns,
// id, cryptword, and permissions,
// where the permissions value is a comma-separated list of permission names.
type PwDB struct {
    db *sql.DB
}

func NewPwDB(db *sql.DB) *PwDB {
  return &PwDB{
    db: db,
  }
}

func (pdb *PwDB) CreatePasswordTable() error {
  query := "CREATE TABLE user(id string, cryptword string, permissions string, primary key(id));"
  _, err := pdb.db.Exec(query)
  return err
}

// Load does nothing when we are using a database.
func (pdb *PwDB) Load() (*users.Users, error) {
  return nil, nil
}

// Save does nothing when we are using a database.
func (pdb *PwDB) Save(_ *users.Users) error {
  return nil
}

func (pdb *PwDB) User(username string) *users.User {
  query := "SELECT cryptword, permissions FROM user WHERE id = :id"
  var cryptword string
  var perms string
  err := pdb.db.QueryRow(query,sql.Named("id", username)).Scan(&cryptword, &perms)
  if err == sql.ErrNoRows {
    return nil          // No matching username found
  }
  if err != nil {
    glog.Errorf("Error scanning for user %q: %v\n", username, err)
    return nil
  }
  user := users.NewUser(username, cryptword, permissions.FromString(perms))
  return user
}

func (pdb *PwDB) SetSaltword(username, cryptword string) {
  if username == "" {
    glog.Errorf("Can't SetSaltword with no username\n")
    return
  }
  // Assume row does not exist, try to insert it.
  iQuery := `INSERT into user(id,cryptword,permissions) values(:id, :cw, "");`
  _, err := pdb.db.Exec(iQuery,sql.Named("cw", cryptword),sql.Named("id", username))
  if err == nil {
    return      // Succeeded
  }
  glog.Infof("INSERT returned err=%v\n", err)   // Expected if the user already exists.
  // If the INSERT failed, assume it was because the row already exists, so try updating it.
  query := "UPDATE user SET cryptword = :cw WHERE id = :id;"
  _, err = pdb.db.Exec(query,sql.Named("cw", cryptword),sql.Named("id", username))
  if err != nil {
    glog.Errorf("Error setting cryptword for user %q: %v\n", username, err)
  }
}

func (pdb *PwDB) UserCount() int {
  var count int
  sql := "SELECT count(*) from user;"
  err := pdb.db.QueryRow(sql).Scan(&count)
  if err != nil {
    glog.Errorf("Error counting user in database: %v\n", err)
    return 0
  }
  return count
}
