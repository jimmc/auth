package auth

import (
  "encoding/json"
  "net/http"
  "net/http/httptest"
  "strconv"
  "testing"
  "time"

  "github.com/jimmc/auth/permissions"
  "github.com/jimmc/auth/store"
  "github.com/jimmc/auth/users"
)

const CanDoSomething permissions.Permission = "something"

func TestRequireAuth(t *testing.T) {
  pf := store.NewPwFile("testdata/pw1.txt")
  h := NewHandler(&Config{
    Prefix: "/pre/",
    Store: pf,
    TokenCookieName: "test_cookie",
    MaxClockSkewSeconds: 2,
  })

  req, err := http.NewRequest("GET", "/api/list/d1", nil)
  if err != nil {
    t.Fatalf("error create auth list request: %v", err)
  }

  // Test the error case, where there is not yet a current user.
  if got, want := CurrentUserHasPermission(req, CanDoSomething), false; got!=want {
    t.Errorf("error checking permission for no current user, got %v, want %v", got, want)
  }

  var reqUser *users.User
  baseFuncF := func(w http.ResponseWriter, r *http.Request) {
    reqUser = CurrentUser(r)
    if got, want := CurrentUserHasPermission(r, CanDoSomething), false; got != want {
        t.Errorf("current user permission: got %v, want %v", got, want)
    }
  }
  baseHandlerF := http.HandlerFunc(baseFuncF)
  baseFuncT := func(w http.ResponseWriter, r *http.Request) {
    reqUser = CurrentUser(r)
    if got, want := CurrentUserHasPermission(r, CanDoSomething), true; got != want {
        t.Errorf("current user permission: got %v, want %v", got, want)
    }
  }
  baseHandlerT := http.HandlerFunc(baseFuncT)

  wrappedFuncF := h.RequireAuthFunc(baseFuncF)
  wrappedFuncT := h.RequireAuthFunc(baseFuncT)
  wrappedHandlerF := h.RequireAuth(baseHandlerF)
  wrappedHandlerT := h.RequireAuth(baseHandlerT)
  wrappedFuncPermT := h.RequirePermissionFunc(baseHandlerT, CanDoSomething)
  wrappedHandlerPermT := h.RequirePermission(baseHandlerT, CanDoSomething)

  rr := httptest.NewRecorder()
  wrappedFuncF(rr, req)
  if got, want := rr.Code, http.StatusUnauthorized; got != want {
    t.Errorf("request without auth in func: got status %d, want %d", got, want)
  }

  rr = httptest.NewRecorder()
  wrappedHandlerF.ServeHTTP(rr, req)
  if got, want := rr.Code, http.StatusUnauthorized; got != want {
    t.Errorf("request without auth in Handler: got status %d, want %d", got, want)
  }

  rr = httptest.NewRecorder()
  user := users.NewUser("user1", "cw1", nil)
  idstr := clientIdString(req)
  cookie := newToken(user, idstr).cookie(h.config.TokenCookieName)
  req.AddCookie(cookie)
  reqUser = nil
  wrappedHandlerF.ServeHTTP(rr, req)
  if got, want := rr.Code, http.StatusOK; got != want {
    t.Errorf("request with auth: got status %d, want %d", got, want)
  }
  if reqUser == nil {
    t.Errorf("authenicated request should carry a current user")
  }
  if got, want := reqUser.Id(), user.Id(); got != want {
    t.Errorf("authenticated userid: got %s, want %s", got, want)
  }
  if got, want := reqUser.HasPermission(CanDoSomething), false; got != want {
    t.Errorf("permission for CanDoSomething: got %v, want %v", got, want)
  }
  wrappedFuncPermT(rr, req)
  if got, want := rr.Code, http.StatusUnauthorized; got != want {
    t.Errorf("request with perm in func: got status %d, want %d", got, want)
  }
  wrappedHandlerPermT.ServeHTTP(rr, req)
  if got, want := rr.Code, http.StatusUnauthorized; got != want {
    t.Errorf("request with perm in Handler: got status %d, want %d", got, want)
  }

  req, err = http.NewRequest("GET", "/api/list/d1", nil)
  if err != nil {
    t.Fatalf("error create auth list request: %v", err)
  }
  rr = httptest.NewRecorder()
  user = users.NewUser("user1", "cw1", permissions.FromString("something"))
  idstr = clientIdString(req)
  cookie = newToken(user, idstr).cookie(h.config.TokenCookieName)
  req.AddCookie(cookie)
  reqUser = nil
  wrappedFuncT(rr, req)
  if got, want := rr.Code, http.StatusOK; got != want {
    t.Errorf("request with auth in func: got status %d, want %d", got, want)
  }
  wrappedHandlerT.ServeHTTP(rr, req)
  if got, want := rr.Code, http.StatusOK; got != want {
    t.Errorf("request with auth in Handler: got status %d, want %d", got, want)
  }
  if reqUser == nil {
    t.Errorf("authenicated request should carry a current user")
  }
  if got, want := reqUser.HasPermission(CanDoSomething), true; got != want {
    t.Errorf("permission for CanDoSomething: got %v, want %v", got, want)
  }
  wrappedFuncPermT(rr, req)
  if got, want := rr.Code, http.StatusUnauthorized; got != want {
    t.Errorf("request with perm in func: got status %d, want %d", got, want)
  }
  wrappedHandlerPermT.ServeHTTP(rr, req)
  if got, want := rr.Code, http.StatusUnauthorized; got != want {
    t.Errorf("request with perm in Handler: got status %d, want %d", got, want)
  }
}

func TestStatus(t *testing.T) {
  pf := store.NewPwFile("testdata/pw1.txt")
  h := NewHandler(&Config{
    Prefix: "/auth/",
    Store: pf,
    TokenCookieName: "test_cookie",
    MaxClockSkewSeconds: 2,
  })
  req, err := http.NewRequest("GET", "/auth/status", nil)   // path is ignored
  if err != nil {
    t.Fatalf("error create auth list request: %v", err)
  }

  rr := httptest.NewRecorder()

  // Check the status while not logged in.
  h.status(rr, req)
  body := rr.Body.Bytes()
  if len(body) == 0 {
    t.Fatalf("response body should not be empty")
  }
  result := &LoginStatus{}
  if err := json.Unmarshal(body, result); err != nil {
    t.Errorf("error unmarshalling json result: %v", err)
  }
  if got, want := result.LoggedIn, false; got != want {
    t.Errorf("wrong login status: got %v, want %v", got, want)
  }
}

func TestLogin(t *testing.T) {
  pf := store.NewPwFile("testdata/pw1.txt")
  h := NewHandler(&Config{
    Prefix: "/auth/",
    Store: pf,
    TokenCookieName: "test_cookie",
    MaxClockSkewSeconds: 2,
  })
  // Define our login info for the HTTP request. The auth code uses
  // FormValue(key) to get the values. We can set those values here
  // using URL query parameters.
  username := "user3"
  password := "pw3"
  cryptword := sha256sum(username + "-" + password)
  seconds := time.Now().Unix()          // Seconds since the epoch.
  secondsstr := strconv.FormatInt(seconds, 10)
  nonceInput := cryptword + "-" + secondsstr
  nonce := sha256sum(nonceInput);
  queryParmString := "userid=" + username + "&nonce=" + nonce + "&time=" + secondsstr
  url := "/auth/login?" + queryParmString
  req, err := http.NewRequest("GET", url, nil)
  if err != nil {
    t.Fatalf("error create auth list request: %v", err)
  }

  rr := httptest.NewRecorder()
  h.login(rr, req)
  body := rr.Body.Bytes()
  if len(body) == 0 {
    t.Fatalf("response body should not be empty")
  }
  if got, want := rr.Code, http.StatusOK; got != want {
    t.Fatalf("login failed: got status %d, want %d; response is %q", got, want, string(body))
  }
  result := &LoginStatus{}
  if err := json.Unmarshal(body, result); err != nil {
    t.Errorf("error unmarshalling json result: %v; response is %q", err, string(body))
  }
  if got, want := result.LoggedIn, true; got != want {
    t.Errorf("wrong login status: got %v, want %v", got, want)
  }
}
