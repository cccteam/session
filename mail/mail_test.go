package mail

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMessage_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		msg     Message
		wantErr string
	}{
		{name: "a complete message is valid", msg: Message{To: "Ada Lovelace <ada@example.com>", Subject: "You are invited", Text: "Follow the link."}},
		{name: "a bare address is valid", msg: Message{To: "ada@example.com", Subject: "You are invited", Text: "Follow the link."}},
		{name: "no recipient", msg: Message{Subject: "s", Text: "t"}, wantErr: "the message has no recipient"},
		{name: "a recipient that is not an address", msg: Message{To: "ada at example", Subject: "s", Text: "t"}, wantErr: `the recipient "ada at example" is not an address`},
		{name: "no subject", msg: Message{To: "ada@example.com", Text: "t"}, wantErr: "the message has no subject"},
		{name: "no body", msg: Message{To: "ada@example.com", Subject: "s"}, wantErr: "the message has no body"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.msg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}

				return
			}
			if err == nil || !contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestRecorder(t *testing.T) {
	t.Parallel()

	r := &Recorder{}
	first := Message{To: "a@example.com", Subject: "one", Text: "1"}
	second := Message{To: "b@example.com", Subject: "two", Text: "2"}
	if err := r.Send(t.Context(), first); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	r.Err = errors.New("the relay is down")
	if err := r.Send(t.Context(), second); err == nil || err.Error() != "the relay is down" {
		t.Fatalf("Send() with Err = %v, want the error set", err)
	}
	if diff := cmp.Diff([]Message{first, second}, r.Messages()); diff != "" {
		t.Errorf("Messages() mismatch (-want +got):\n%s", diff)
	}
}

func TestLog(t *testing.T) {
	t.Parallel()

	if err := (Log{}).Send(t.Context(), Message{To: "a@example.com", Subject: "one", Text: "https://example.com/login?verify=abc"}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := (Log{}).Send(t.Context(), Message{To: "a@example.com"}); err == nil {
		t.Fatal("Send() of a message without a subject or body = nil, want the validation error")
	}
}

func contains(s, sub string) bool {
	return len(sub) <= len(s) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}

	return -1
}
