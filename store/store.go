package store

import (
    "github.com/jimmc/auth/users"
)

// The Store interface is used by our classes that need to load
// and save the user/password/premissions data.
type Store interface {
    Load() (*users.Users, error)      // Load all our data
    Save(*users.Users) error          // Save all our data
}
