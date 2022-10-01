package auth

import (
  "net/http"
  "net/http/httptest"
  "testing"

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
  baseHandlerF := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    reqUser = CurrentUser(r)
    if got, want := CurrentUserHasPermission(r, CanDoSomething), false; got != want {
        t.Errorf("current user permission: got %v, want %v", got, want)
    }
  })
  baseHandlerT := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    reqUser = CurrentUser(r)
    if got, want := CurrentUserHasPermission(r, CanDoSomething), true; got != want {
        t.Errorf("current user permission: got %v, want %v", got, want)
    }
  })
  wrappedHandlerF := h.RequireAuth(baseHandlerF)
  wrappedHandlerT := h.RequireAuth(baseHandlerT)

  rr := httptest.NewRecorder()
  wrappedHandlerF.ServeHTTP(rr, req)
  if got, want := rr.Code, http.StatusUnauthorized; got != want {
    t.Errorf("request without auth: got status %d, want %d", got, want)
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
  wrappedHandlerT.ServeHTTP(rr, req)
  if got, want := rr.Code, http.StatusOK; got != want {
    t.Errorf("request with auth: got status %d, want %d", got, want)
  }
  if reqUser == nil {
    t.Errorf("authenicated request should carry a current user")
  }
  if got, want := reqUser.HasPermission(CanDoSomething), true; got != want {
    t.Errorf("permission for CanDoSomething: got %v, want %v", got, want)
  }
}
