package store

import (
    "github.com/jimmc/auth/users"
)

// The Store interface is used by our classes that need to load
// and save the user/password/premissions data.
type Store interface {
    Load() error           // Load our data before other operations
    Save() error           // Save our data after other operations
    User(username string) *users.User         // Retrieve a user record by id
    SetSaltword(username, saltword string)  // Set the saltword for a user
    UserCount() int             // Get the number of users in our records
}
