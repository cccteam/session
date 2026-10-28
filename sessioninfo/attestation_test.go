package sessioninfo

import "testing"

func TestAttestationOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		amr      []string
		declared bool
		want     Attestation
	}{
		{name: "mfa in amr is evidence", amr: []string{"pwd", "mfa"}, want: AttestedByEvidence},
		{name: "mfa in amr is evidence whatever the case", amr: []string{"MFA"}, want: AttestedByEvidence},
		{name: "evidence wins over the declaration", amr: []string{"pwd", "mfa"}, declared: true, want: AttestedByEvidence},
		{name: "a declared connection without evidence is a declaration", amr: []string{"pwd"}, declared: true, want: AttestedByDeclaration},
		{name: "a declared connection with no amr at all is a declaration", declared: true, want: AttestedByDeclaration},
		{name: "one method named in amr is not evidence of a second", amr: []string{"otp"}, want: NotAttested},
		{name: "nothing vouches", amr: []string{"pwd"}, want: NotAttested},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := AttestationOf(tt.amr, tt.declared); got != tt.want {
				t.Errorf("AttestationOf(%v, %v) = %q, want %q", tt.amr, tt.declared, got, tt.want)
			}
		})
	}
}

func TestAttestation_Method(t *testing.T) {
	t.Parallel()

	tests := []struct {
		attestation Attestation
		want        AuthMethod
	}{
		{attestation: AttestedByEvidence, want: MethodAttestedByEvidence},
		{attestation: AttestedByDeclaration, want: MethodAttestedByDeclaration},
		{attestation: NotAttested, want: ""},
	}
	for _, tt := range tests {
		if got := tt.attestation.Method(); got != tt.want {
			t.Errorf("Attestation(%q).Method() = %q, want %q", tt.attestation, got, tt.want)
		}
		if got := tt.want.Attests(); got != (tt.want != "") {
			t.Errorf("AuthMethod(%q).Attests() = %v, want %v", tt.want, got, tt.want != "")
		}
	}
	for _, m := range []AuthMethod{MethodPassword, MethodAzure, MethodGoogle, MethodEmailCode, MethodTrustedDevice, MethodApplication} {
		if m.Attests() {
			t.Errorf("AuthMethod(%q).Attests() = true, want false", m)
		}
	}
}
