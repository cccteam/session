package session

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/sessioninfo"
	"github.com/gorilla/securecookie"
	"golang.org/x/crypto/bcrypt"
)

func TestPasswordSession_Login_InvalidJSON(t *testing.T) {
	t.Parallel()

	ps, storage, creds, perms := newTestPasswordSession(t, nil, nil, nil)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString("{"))

	ps.Login().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}

	if storage.called {
		t.Fatal("expected storage not to be called for invalid payload")
	}
	if creds.called {
		t.Fatal("expected credential reader not to be called for invalid payload")
	}
	if perms.called {
		t.Fatal("expected permissions not to be queried for invalid payload")
	}

	if cookies := recorder.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("expected no cookies to be set, got %d", len(cookies))
	}
}

func TestPasswordSession_Login_MissingFields(t *testing.T) {
	t.Parallel()

	ps, storage, creds, perms := newTestPasswordSession(t, nil, nil, nil)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(`{"username":" ","password":""}`))

	ps.Login().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}

	if storage.called {
		t.Fatal("expected storage not to be called for missing fields")
	}
	if creds.called {
		t.Fatal("expected credential reader not to be called for missing fields")
	}
	if perms.called {
		t.Fatal("expected permissions not to be queried for missing fields")
	}
}

func TestPasswordSession_Login_UserNotFound(t *testing.T) {
	t.Parallel()

	creds := &stubCredentialReader{
		err: httpio.NewNotFoundMessagef("user %s not found", "missing"),
	}
	ps, storage, creds, perms := newTestPasswordSession(t, nil, creds, nil)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(`{"username":"missing","password":"secret"}`))

	ps.Login().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
	}

	if storage.called {
		t.Fatal("expected storage not to be called when user is not found")
	}
	if !creds.called {
		t.Fatal("expected credential reader to be called")
	}
	if perms.called {
		t.Fatal("expected permissions not to be queried when user is not found")
	}
}

func TestPasswordSession_Login_InvalidPassword(t *testing.T) {
	t.Parallel()

	hashed, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	creds := &stubCredentialReader{hash: string(hashed)}
	ps, storage, creds, perms := newTestPasswordSession(t, nil, creds, nil)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(`{"username":"alice","password":"wrong"}`))

	ps.Login().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
	}

	if storage.called {
		t.Fatal("expected storage not to be called for invalid password")
	}
	if !creds.called {
		t.Fatal("expected credential reader to be called")
	}
	if perms.called {
		t.Fatal("expected permissions not to be queried for invalid password")
	}
}

func TestPasswordSession_Login_NewSessionError(t *testing.T) {
	t.Parallel()

	hashed, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	storage := &stubPasswordStorage{
		newSessionFn: func(_ context.Context, _ string) (ccc.UUID, error) {
			return ccc.NilUUID, assertError("failed to create session")
		},
	}
	creds := &stubCredentialReader{hash: string(hashed)}
	ps, storage, creds, perms := newTestPasswordSession(t, storage, creds, nil)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(`{"username":"alice","password":"secret"}`))

	ps.Login().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, recorder.Code)
	}

	if !storage.called {
		t.Fatal("expected storage to be called when creating session")
	}
	if !creds.called {
		t.Fatal("expected credential reader to be called")
	}
	if perms.called {
		t.Fatal("expected permissions not to be queried when session creation fails")
	}
}

func TestPasswordSession_Login_Success(t *testing.T) {
	t.Parallel()

	hashed, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	expectedID := ccc.Must(ccc.UUIDFromString("8b6f4212-18c0-4e60-9d82-61e8d4d3e4f1"))
	storage := &stubPasswordStorage{
		newSessionFn: func(_ context.Context, _ string) (ccc.UUID, error) {
			return expectedID, nil
		},
	}
	creds := &stubCredentialReader{hash: string(hashed)}
	perms := &stubPermissionManager{
		perms: accesstypes.UserPermissionCollection{
			accesstypes.GlobalDomain: {
				accesstypes.GlobalResource: {accesstypes.Permission("List")},
			},
		},
	}
	ps, storage, creds, perms := newTestPasswordSession(t, storage, creds, perms)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(`{"username":"alice","password":"secret"}`))

	ps.Login().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	if !storage.called {
		t.Fatal("expected storage to be called")
	}
	if storage.username != "alice" {
		t.Fatalf("expected username 'alice', got %s", storage.username)
	}
	if !creds.called {
		t.Fatal("expected credential reader to be called")
	}
	if !perms.called {
		t.Fatal("expected permissions to be queried")
	}

	resp := recorder.Result()
	defer resp.Body.Close()
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected cookies to be set after successful login")
	}

	result := struct {
		Authenticated bool                                 `json:"authenticated"`
		Username      string                               `json:"username"`
		Permissions   accesstypes.UserPermissionCollection `json:"permissions"`
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !result.Authenticated {
		t.Fatal("expected authenticated flag to be true")
	}
	if result.Username != "alice" {
		t.Fatalf("expected username 'alice', got %s", result.Username)
	}
	if diff := cmpPermissions(result.Permissions, perms.perms); diff != "" {
		t.Fatalf("permissions mismatch: %s", diff)
	}
}

// helper structures and functions for tests

type stubPasswordStorage struct {
	newSessionFn func(context.Context, string) (ccc.UUID, error)
	called       bool
	username     string
}

func (s *stubPasswordStorage) DestroySession(context.Context, ccc.UUID) error {
	return nil
}

func (s *stubPasswordStorage) UpdateSessionActivity(context.Context, ccc.UUID) error {
	return nil
}

func (s *stubPasswordStorage) Session(context.Context, ccc.UUID) (*sessioninfo.SessionInfo, error) {
	return nil, nil
}

func (s *stubPasswordStorage) NewSession(ctx context.Context, username string) (ccc.UUID, error) {
	s.called = true
	s.username = username
	if s.newSessionFn != nil {
		return s.newSessionFn(ctx, username)
	}

	return ccc.NilUUID, nil
}

type stubCredentialReader struct {
	hash   string
	err    error
	called bool
}

func (s *stubCredentialReader) HashedPassword(context.Context, string) (string, error) {
	s.called = true
	if s.err != nil {
		return "", s.err
	}

	return s.hash, nil
}

type stubPermissionManager struct {
	perms  accesstypes.UserPermissionCollection
	err    error
	called bool
}

func (s *stubPermissionManager) UserPermissions(context.Context, accesstypes.User, ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error) {
	s.called = true
	if s.err != nil {
		return nil, s.err
	}

	return s.perms, nil
}

func newTestPasswordSession(t *testing.T, storage *stubPasswordStorage, creds *stubCredentialReader, perms *stubPermissionManager) (*PasswordSession, *stubPasswordStorage, *stubCredentialReader, *stubPermissionManager) {
	t.Helper()
	if storage == nil {
		storage = &stubPasswordStorage{}
	}
	if creds == nil {
		creds = &stubCredentialReader{}
	}
	if perms == nil {
		perms = &stubPermissionManager{}
	}

	key := []byte("0123456789abcdef0123456789abcdef")
	sc := securecookie.New(key, key)

	session := NewPassword(
		creds,
		storage,
		perms,
		func(handler func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				if err := handler(w, r); err != nil {
					_ = err
				}
			}
		},
		sc,
		time.Minute,
	)

	return session, storage, creds, perms
}

func cmpPermissions(got, want accesstypes.UserPermissionCollection) string {
	if len(got) != len(want) {
		return "permission length mismatch"
	}
	for domain, resources := range want {
		gr, ok := got[domain]
		if !ok {
			return "missing domain"
		}
		if len(gr) != len(resources) {
			return "resource length mismatch"
		}
		for res, perms := range resources {
			gp, ok := gr[res]
			if !ok {
				return "missing resource"
			}
			if len(gp) != len(perms) {
				return "permission count mismatch"
			}
			for i, perm := range perms {
				if gp[i] != perm {
					return "permission mismatch"
				}
			}
		}
	}

	return ""
}

type assertError string

func (e assertError) Error() string {
	return string(e)
}
