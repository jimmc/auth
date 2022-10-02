package store

import (
    "github.com/jimmc/auth/users"
)

// The Store interface is used by our classes that need to load
// and save the user/password/premissions data.
type Store interface {
    Load() error           // Load our data before other operations
    Save() error           // Save our data after other operations
    User(userid string) *users.User         // Retrieve a user record by id
    SetCryptword(userid, cryptword string)  // Set the cryptword for a user
    UserCount() int             // Get the number of users in our records
}
