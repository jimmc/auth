package main

/* This is an example of a simple http server that uses the auth module.
 */

import (
  "encoding/json"
  "fmt"
  "net/http"
  "os"
  "strconv"

  "github.com/jimmc/auth/auth"
  "github.com/jimmc/auth/store"
)

const (
  useAuth = true       // True to use the auth package; false shows code without auth.
  port = 8018           // The port our http server listens on.
  passwordFilePath = "pw.txt"  // Relative to this directory.
  maxClockSkewSeconds = 5
  uiRoot = "_ui"        // Relative to this directory.
)

func main() {
  os.Exit(doMain())
}

// doMain return 0 if the program is exiting with no errors.
func doMain() int {
  apiPrefix := "/api/"
  apiHandler := newApiHandler(apiPrefix)         // We will require auth for these calls.

  openPrefix := "/open/"
  openHandler := newOpenHandler(openPrefix)       // These calls will not require auth.

  authPrefix := "/auth/"
  authStore := store.NewPwFile(passwordFilePath)
  authHandler := auth.NewHandler(&auth.Config{
    Prefix: authPrefix,
    Store: authStore,
    TokenCookieName: "AUTH_EXAMPLE",
    MaxClockSkewSeconds: maxClockSkewSeconds,
  })

  mux := http.NewServeMux()
  uiPrefix := "/ui/"
  uiFileHandler := http.FileServer(http.Dir(uiRoot))
  mux.Handle(uiPrefix, http.StripPrefix(uiPrefix, uiFileHandler)) // ui handler supples html pages.
  if useAuth {
    mux.Handle(apiPrefix, authHandler.RequireAuth(apiHandler))
  } else {
    mux.Handle(apiPrefix, apiHandler)
  }
  mux.Handle(openPrefix, openHandler)
  if useAuth {
    mux.Handle(authPrefix, authHandler.ApiHandler)        // Wire in login and logout calls.
  }
  mux.HandleFunc("/", redirectToUi)
  fmt.Printf("Starting example server on port %d\n", port)
  err := http.ListenAndServe(":"+strconv.Itoa(port), mux)
  fmt.Printf("Error running server: %v\n", err)
  return 1
}

// We can add any additional functions to this handler that we
// want to be open (no authentication).
func newOpenHandler(prefix string) http.Handler {
  mux := http.NewServeMux()
  mux.HandleFunc(prefix + "hello", hello)
  return mux
}

// We can add any additional functions to this handler that we
// want to require authentication.
func newApiHandler(prefix string) http.Handler {
  mux := http.NewServeMux()
  mux.HandleFunc(prefix + "secret", secret)
  return mux
}

func marshalAndReply(w http.ResponseWriter, result interface{}) {
  b, err := json.MarshalIndent(result, "", "  ")
  if err != nil {
    http.Error(w, fmt.Sprintf("Failed to marshall json results: %v", err), http.StatusInternalServerError)
    return
  }
  w.WriteHeader(http.StatusOK)
  w.Write(b)
}

func redirectToUi(w http.ResponseWriter, r *http.Request) {
  http.Redirect(w, r, "/ui/", http.StatusTemporaryRedirect)
}

// Below here are all our various application handlers.
// Authentication is handled by the auth package before getting here.

func hello(w http.ResponseWriter, r *http.Request) {
  marshalAndReply(w, "hello")
}

func secret(w http.ResponseWriter, r *http.Request) {
  marshalAndReply(w, "secret")
}
