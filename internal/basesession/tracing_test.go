package basesession

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/mock/mock_cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	"github.com/google/go-cmp/cmp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	gomock "go.uber.org/mock/gomock"
)

var (
	spanExporter     *tracetest.InMemoryExporter
	spanExporterOnce sync.Once
)

// spanRecorder installs, once per test binary, a global tracer provider that exports
// ended spans synchronously into memory, and returns the exporter. Tests run in
// parallel and share it, so each filters the spans by its own session ID.
func spanRecorder() *tracetest.InMemoryExporter {
	spanExporterOnce.Do(func() {
		spanExporter = tracetest.NewInMemoryExporter()
		otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSyncer(spanExporter)))
	})

	return spanExporter
}

// spansForSession returns the exported spans carrying impersonation.session_id == id.
func spansForSession(exporter *tracetest.InMemoryExporter, id ccc.UUID) []tracetest.SpanStub {
	var spans []tracetest.SpanStub
	exported := exporter.GetSpans()
	for i := range exported {
		for _, kv := range exported[i].Attributes {
			if kv.Key == sessioninfo.AttrImpersonationSessionID && kv.Value.AsString() == id.String() {
				spans = append(spans, exported[i])

				break
			}
		}
	}

	return spans
}

func attributeMap(kvs []attribute.KeyValue) map[string]string {
	m := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		m[string(kv.Key)] = kv.Value.AsString()
	}

	return m
}

func TestBaseSession_ValidateSession_SpanEvidence(t *testing.T) {
	t.Parallel()
	exporter := spanRecorder()

	sourceID := ccc.Must(ccc.NewUUID())
	record := func(id ccc.UUID) *sessioninfo.Impersonation {
		return &sessioninfo.Impersonation{
			SessionID:       id,
			Actor:           "alice@example.com",
			ActorRealm:      "admin-portal",
			SourceSessionID: ccc.NullUUID{UUID: sourceID, Valid: true},
			Principal:       accesstypes.UserPrincipal("bob@partner.org"),
			Mask:            accesstypes.MaskPermissions(accesstypes.List, accesstypes.Read),
			ExpiresAt:       time.Now().Add(time.Hour),
		}
	}
	impersonationAttrs := func(id ccc.UUID) map[string]string {
		return map[string]string{
			sessioninfo.AttrImpersonationActor:           "alice@example.com",
			sessioninfo.AttrImpersonationActorRealm:      "admin-portal",
			sessioninfo.AttrImpersonationPrincipalKind:   "User",
			sessioninfo.AttrImpersonationPrincipal:       "bob@partner.org",
			sessioninfo.AttrImpersonationMask:            "List,Read",
			sessioninfo.AttrImpersonationSessionID:       id.String(),
			sessioninfo.AttrImpersonationSourceSessionID: sourceID.String(),
		}
	}

	tests := []struct {
		name         string
		impersonated bool
		expired      bool
		resolver     func(context.Context) (accesstypes.Principal, error)
		want         func(id ccc.UUID) map[string]string
	}{
		{
			name: "an ordinary request stamps enduser.id",
			want: func(ccc.UUID) map[string]string { return map[string]string{attrEndUserID: "bob@partner.org"} },
		},
		{
			name:         "an impersonated request stamps the record and enduser.id",
			impersonated: true,
			want: func(id ccc.UUID) map[string]string {
				m := impersonationAttrs(id)
				m[attrEndUserID] = "bob@partner.org"

				return m
			},
		},
		{
			name:         "a resolver that changes the subject adds the principal attributes",
			impersonated: true,
			resolver:     func(context.Context) (accesstypes.Principal, error) { return accesstypes.RolePrincipal("Editor"), nil },
			want: func(id ccc.UUID) map[string]string {
				m := impersonationAttrs(id)
				m[attrEndUserID] = "bob@partner.org"
				m[sessioninfo.AttrPrincipalKind] = "Role"
				m[sessioninfo.AttrPrincipal] = "Editor"

				return m
			},
		},
		{
			name:         "a refused (expired) impersonated request still names the actor and principal, without enduser.id",
			impersonated: true,
			expired:      true,
			want:         impersonationAttrs,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			newSession := func(id ccc.UUID) *sessioninfo.SessionData {
				session := &sessioninfo.SessionData{SessionInfo: &sessioninfo.SessionInfo{ID: id, Username: "bob@partner.org", UpdatedAt: time.Now()}}
				if tt.impersonated {
					session.Impersonation = record(id)
				}
				session.Expired = tt.expired

				return session
			}
			newBase := func(t *testing.T, id ccc.UUID) *BaseSession {
				t.Helper()
				ctrl := gomock.NewController(t)
				storage := mock_sessionstorage.NewMockBaseStore(ctrl)
				storage.EXPECT().Session(gomock.Any(), id).Return(newSession(id), nil)
				if tt.expired && tt.impersonated {
					storage.EXPECT().EndImpersonation(gomock.Any(), id, sessioninfo.ImpersonationEndedByExpiry).Return(nil)
				}

				return &BaseSession{
					SessionTimeout:    time.Minute,
					Storage:           storage,
					PrincipalResolver: tt.resolver,
					Handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
						return func(w http.ResponseWriter, r *http.Request) {
							if err := handler(w, r); err != nil {
								_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
							}
						}
					},
				}
			}

			// The middleware stamps the span current in the request context: the server span.
			t.Run("middleware stamps the request span", func(t *testing.T) {
				t.Parallel()
				id := ccc.Must(ccc.NewUUID())
				s := newBase(t, id)

				ctx, root := otel.Tracer("test").Start(context.Background(), "server "+id.String())
				ctx = context.WithValue(ctx, sessioninfo.CTXSessionID, id)
				rr := httptest.NewRecorder()
				s.ValidateSession(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
					ServeHTTP(rr, httptest.NewRequestWithContext(ctx, http.MethodGet, "/", http.NoBody))
				root.End()

				if (rr.Code == http.StatusUnauthorized) != tt.expired {
					t.Fatalf("status = %d, wantExpired %v", rr.Code, tt.expired)
				}
				assertSpanAttributes(t, exporter, "server "+id.String(), tt.want(id))
			})

			// The API path stamps the span current in the context it receives: the caller's.
			t.Run("API path stamps the caller's span", func(t *testing.T) {
				t.Parallel()
				id := ccc.Must(ccc.NewUUID())
				s := newBase(t, id)

				ctx, caller := otel.Tracer("test").Start(context.Background(), "caller "+id.String())
				ctx = context.WithValue(ctx, sessioninfo.CTXSessionID, id)
				_, err := s.ValidateSessionAPI(ctx)
				caller.End()

				if (err != nil) != tt.expired {
					t.Fatalf("ValidateSessionAPI() error = %v, wantExpired %v", err, tt.expired)
				}
				assertSpanAttributes(t, exporter, "caller "+id.String(), tt.want(id))
			})
		})
	}
}

// assertSpanAttributes finds the one exported span named name and compares its
// attributes with want.
func assertSpanAttributes(t *testing.T, exporter *tracetest.InMemoryExporter, name string, want map[string]string) {
	t.Helper()

	var found []tracetest.SpanStub
	exported := exporter.GetSpans()
	for i := range exported {
		if exported[i].Name == name {
			found = append(found, exported[i])
		}
	}
	if len(found) != 1 {
		t.Fatalf("spans named %q = %d, want 1", name, len(found))
	}
	if diff := cmp.Diff(want, attributeMap(found[0].Attributes)); diff != "" {
		t.Errorf("span %q attributes mismatch (-want +got):\n%s", name, diff)
	}
}

func TestBaseSession_StartImpersonatedSession_SpanEvidence(t *testing.T) {
	t.Parallel()
	exporter := spanRecorder()

	ctrl := gomock.NewController(t)
	sessionID := ccc.Must(ccc.NewUUID())
	storage := mock_sessionstorage.NewMockBaseStore(ctrl)
	storage.EXPECT().CreateImpersonatedSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(sessionID, nil)
	cookieHandler := mock_cookie.NewMockHandler(ctrl)
	cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), true, sessionID).Return(cookie.NewValues())
	cookieHandler.EXPECT().CreateXSRFTokenCookie(gomock.Any(), sessionID)

	s := &BaseSession{Storage: storage, CookieHandler: cookieHandler}
	imp := &sessioninfo.Impersonation{Actor: "alice", Principal: accesstypes.RolePrincipal("Editor")}
	req := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: "alice"}
	if _, err := s.StartImpersonatedSession(context.Background(), httptest.NewRecorder(), req, imp); err != nil {
		t.Fatalf("StartImpersonatedSession() error = %v", err)
	}

	spans := spansForSession(exporter, sessionID)
	if len(spans) != 1 || spans[0].Name != "BaseSession.StartImpersonatedSession()" {
		t.Fatalf("spans for session = %v, want the establishing span", spanNames(spans))
	}
	want := map[string]string{
		sessioninfo.AttrImpersonationActor:         "alice",
		sessioninfo.AttrImpersonationPrincipalKind: "Role",
		sessioninfo.AttrImpersonationPrincipal:     "Editor",
		sessioninfo.AttrImpersonationMask:          "unrestricted",
		sessioninfo.AttrImpersonationSessionID:     sessionID.String(),
	}
	if diff := cmp.Diff(want, attributeMap(spans[0].Attributes)); diff != "" {
		t.Errorf("establishing span attributes mismatch (-want +got):\n%s", diff)
	}
	if len(spans[0].Events) != 1 || spans[0].Events[0].Name != "impersonation.Started" {
		t.Errorf("establishing span events = %d, want one impersonation.Started", len(spans[0].Events))
	}
}

func spanNames(spans []tracetest.SpanStub) []string {
	names := make([]string, len(spans))
	for i := range spans {
		names[i] = spans[i].Name
	}

	return names
}

func TestBaseSession_EmitImpersonationEvent_SpanEvent(t *testing.T) {
	t.Parallel()
	exporter := spanRecorder()

	sessionID := ccc.Must(ccc.NewUUID())
	ended := time.Now()
	imp := &sessioninfo.Impersonation{
		SessionID: sessionID,
		Actor:     "alice",
		Principal: accesstypes.RolePrincipal("Editor"),
		EndedAt:   &ended,
		EndReason: sessioninfo.ImpersonationEndedByRevocation,
	}

	ctx, span := otel.Tracer("test").Start(context.Background(), "request")
	if err := (&BaseSession{}).EmitImpersonationEvent(ctx, sessioninfo.ImpersonationWriteBlocked, imp, "POST /api/x"); err != nil {
		t.Fatalf("EmitImpersonationEvent() error = %v", err)
	}
	span.End()

	var events []sdktrace.Event
	for _, exported := range exporter.GetSpans() {
		for _, event := range exported.Events {
			if m := attributeMap(event.Attributes); m[sessioninfo.AttrImpersonationSessionID] == sessionID.String() {
				events = append(events, event)
			}
		}
	}
	if len(events) != 1 || events[0].Name != "impersonation.WriteBlocked" {
		t.Fatalf("events = %d, want one impersonation.WriteBlocked", len(events))
	}
	want := map[string]string{
		sessioninfo.AttrImpersonationActor:         "alice",
		sessioninfo.AttrImpersonationPrincipalKind: "Role",
		sessioninfo.AttrImpersonationPrincipal:     "Editor",
		sessioninfo.AttrImpersonationMask:          "unrestricted",
		sessioninfo.AttrImpersonationSessionID:     sessionID.String(),
		"impersonation.operation":                  "POST /api/x",
		"impersonation.end_reason":                 "Revoked",
	}
	if diff := cmp.Diff(want, attributeMap(events[0].Attributes)); diff != "" {
		t.Errorf("event attributes mismatch (-want +got):\n%s", diff)
	}
}
