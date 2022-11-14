package auth

import (
  "context"
  "encoding/json"
  "fmt"
  "net/http"
  "time"

  "github.com/golang/glog"

  "github.com/jimmc/auth/permissions"
  "github.com/jimmc/auth/users"
)

type LoginStatus struct {
  LoggedIn bool
  Permissions string
}

const (
  ctxUserKey = "AuthUser"       // Make it a string that the caller can access. Useful for testing.
)

func (h *Handler) initApiHandler() {
  mux := http.NewServeMux()
  mux.HandleFunc(h.apiPrefix("login"), h.login)
  mux.HandleFunc(h.apiPrefix("logout"), h.logout)
  mux.HandleFunc(h.apiPrefix("status"), h.status)
  h.ApiHandler = mux
}

// RequireAuth enforces Authentication.
// Use this function to wrap the call to your handler when you
// call http.NewServeMux().Handle().
// If the user is not authenticated, it returns StatusUnauthorized
// with the message "not authenticated".
// See also RequirePermission and RequireAuthFunc.
func (h *Handler) RequireAuth(httpHandler http.Handler) http.Handler {
  return h.RequirePermission(httpHandler, permissions.NoPermission)
}

// RequirePermission enforces Authentication and having one permission.
// Use this function to wrap the call to your handler when you
// call http.NewServeMux().Handle().
// If the user is not authenticated, it returns StatusUnauthorized
// with the message "not authenticated".
// If the user does not have the specified permission, it returns
// StatusUnauthorized with a the message "not authorized".
// If both checks pass, the specified handler is called.
// For more control, you can use RequireAuth instead of RequirePermission,
// then call CurrentUserHasPermission to check that condition.
// See also RequirePermissionFunc.
func (h *Handler) RequirePermission(httpHandler http.Handler, perm permissions.Permission) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
    currentUser := CurrentUser(r)
    username := "(no current user)"
    if currentUser != nil {
      username = currentUser.Id()
    }
    tokenKey := cookieValue(r, h.config.TokenCookieName)
    idstr := clientIdString(r)
    token, valid := currentToken(tokenKey, idstr);
    if !valid {
      // No token, or token is not valid
      glog.V(2).Infof("No token or token is not valid for user %q", username)
      http.Error(w, "Not authenticated", http.StatusUnauthorized)
      return
    }
    if perm != permissions.NoPermission {
      if !CurrentUserHasPermission(r, perm) {
        glog.V(2).Infof("Not authorized: user %q does not have permission %q", username, perm)
        http.Error(w, "Not authorized", http.StatusUnauthorized)
        return
      }
    }
    token.updateTimeout(h.config.TokenTimeoutDuration)
    http.SetCookie(w, token.cookie(h.config.TokenCookieName)) // Set the renewed cookie
    http.SetCookie(w, token.timeoutCookie(h.config.TokenCookieName)) // Set the timeout cookie
    user := token.User()
    rwcu := requestWithContextUser(r, user)
    httpHandler.ServeHTTP(w, rwcu)
  })
}

// RequireAuthFunc is like RequireAuth, except that it is for use to wrap
// a handler func rather than a Handler.
func (h *Handler) RequireAuthFunc(handleFunc func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
  return h.RequireAuth(http.HandlerFunc(handleFunc)).ServeHTTP
}

// RequirePermissionFunc is like RequirePermission, except that it is for use to wrap
// a handler func rather than a Handler.
func (h *Handler) RequirePermissionFunc(handleFunc func(http.ResponseWriter, *http.Request), perm permissions.Permission) func(http.ResponseWriter, *http.Request) {
  return h.RequirePermission(http.HandlerFunc(handleFunc), perm).ServeHTTP
}

func requestWithContextUser(r *http.Request, user *users.User) *http.Request {
  cwv := context.WithValue(r.Context(), ctxUserKey, user)
  return r.WithContext(cwv)
}

// CurrentUser returns the user from the request context, or nil if no user found there.
func CurrentUser(r *http.Request) *users.User {
  v := r.Context().Value(ctxUserKey)
  if v == nil {
    return nil
  }
  return v.(*users.User)
}

// CurrentUsername returns the current username, or a placeholder string if
// there is no current user.
func CurrentUsername(r *http.Request) string {
  user := CurrentUser(r)
  if user == nil {
    return "(no current user)"
  }
  return user.Id()
}

// CurrentUserHasPermissions returns true if the user from the request context has
// the specified permission, or false if they do not, or if there is no user found.
func CurrentUserHasPermission(r *http.Request, perm permissions.Permission) bool {
  user := CurrentUser(r)
  if user == nil {
    return false
  }
  return user.HasPermission(perm)
}

// CurrentPermissions returns the set of permissions for the user from the
// request context, or an empty list if there is no user found.
func CurrentPermissions(r *http.Request) *permissions.Permissions {
  user := CurrentUser(r)
  if user == nil {
    return permissions.FromString("")
  }
  return user.Permissions()
}

func (h *Handler) apiPrefix(s string) string {
  return fmt.Sprintf("%s%s/", h.config.Prefix, s)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
  username := r.FormValue("username")
  glog.V(4).Infof("login username=%s", username)
  hashword := r.FormValue("hashword")
  glog.V(4).Infof("login hashword=%s", hashword)

  user := h.config.Store.User(username)
  if user != nil && h.hashwordIsValid(username, hashword) {
    // OK to log in; generate a bearer token and put in a cookie
    idstr := clientIdString(r)
    token := newToken(user, idstr, h.config.TokenTimeoutDuration, h.config.TokenExpiryDuration)
    http.SetCookie(w, token.cookie(h.config.TokenCookieName))
    http.SetCookie(w, token.timeoutCookie(h.config.TokenCookieName))
  } else {
    if user==nil {
      glog.Errorf("user is nil in login")
    }
    http.Error(w, "Invalid username or password", http.StatusUnauthorized)
    return
  }

  result := &LoginStatus{
    LoggedIn: true,
    Permissions: user.PermissionsString(),
  }
  b, err := json.MarshalIndent(result, "", "  ")
  if err != nil {
    http.Error(w, fmt.Sprintf("Failed to marshall login status: %v", err), http.StatusInternalServerError)
    return
  }
  w.WriteHeader(http.StatusOK)
  w.Write(b)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
  // Clear our token cookie
  tokenCookie := &http.Cookie{
    Name: h.config.TokenCookieName,
    Path: "/",
    Value: "",
    Expires: time.Now().AddDate(-1, 0, 0),
  }
  timeoutCookie := &http.Cookie{
    Name: h.config.TokenCookieName+"_TIMEOUT",
    Path: "/",
    Value: "",
    Expires: time.Now().AddDate(-1, 0, 0),
  }
  http.SetCookie(w, tokenCookie)
  http.SetCookie(w, timeoutCookie)
  w.WriteHeader(http.StatusOK)
  w.Write([]byte(`{"status": "ok"}`))
}

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
  tokenKey := cookieValue(r, h.config.TokenCookieName)
  idstr := clientIdString(r)
  token, loggedIn := currentToken(tokenKey, idstr)
  result := &LoginStatus{
    LoggedIn: loggedIn,
  }
  if loggedIn {
    token.updateTimeout(h.config.TokenTimeoutDuration)
    http.SetCookie(w, token.cookie(h.config.TokenCookieName)) // Set the renewed cookie
    http.SetCookie(w, token.timeoutCookie(h.config.TokenCookieName))
    result.Permissions = token.User().PermissionsString()
  }

  b, err := json.MarshalIndent(result, "", "  ")
  if err != nil {
    http.Error(w, fmt.Sprintf("Failed to marshall login status: %v", err), http.StatusInternalServerError)
    return
  }
  w.WriteHeader(http.StatusOK)
  w.Write(b)
}

func clientIdString(r *http.Request) string {
  return r.UserAgent()
}

func cookieValue(r *http.Request, cookieName string) string {
  cookie, err := r.Cookie(cookieName)
  if err != nil {
    return ""
  }
  return cookie.Value
}

// AddTokenCookie adds a cookie to the request to make us be logged in, for testing.
func AddTokenCookieForTesting(r *http.Request, config *Config) error {
  config = fillConfigDefaults(config)
  user := CurrentUser(r)
  if user==nil {
    return fmt.Errorf("No user in request")
  }
  idstr := clientIdString(r)
  token := newToken(user, idstr, config.TokenTimeoutDuration, config.TokenExpiryDuration)
  c := token.cookie(config.TokenCookieName)
  r.AddCookie(c)
  return nil
}

// fillConfigDefaults fills in the config with default values,
// or returns a new config if nil is passed in.
func fillConfigDefaults(config *Config) *Config {
  if config == nil {
    config = &Config{}
  }
  if config.TokenTimeoutDuration == 0 {
    config.TokenTimeoutDuration = defaultTokenTimeoutDuration
  }
  if config.TokenExpiryDuration == 0 {
    config.TokenExpiryDuration = defaultTokenExpiryDuration
  }
  if config.TokenCookieName == "" {
    config.TokenCookieName = "test_cookie"
  }
  return config
}
