package openshift

import (
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"net/http"
	"reflect"
	"testing"
)

type mockAuthRequestHandler struct {
}

type mockAuthorizer struct {
}

func TestParseSubjectAccessReviews(t *testing.T) {

	tests := []struct {
		sar            string
		expectedResult []string
	}{
		{
			sar: `{"foo":"bar"}`,
			expectedResult: []string{
				`{"foo":"bar","scopes":[]}`,
			},
		},
		{
			sar: `[{"foo":"bar"}, {"baz":"bad"}]`,
			expectedResult: []string{
				`{"foo":"bar","scopes":[]}`,
				`{"baz":"bad","scopes":[]}`,
			},
		},
	}

	for _, test := range tests {
		result, err := parseSubjectAccessReviews(test.sar)
		if err != nil {
			t.Fatalf("unexpected error %s", err.Error())
		}
		if !reflect.DeepEqual(result, test.expectedResult) {
			t.Fatalf("expected %v, got %v", test.expectedResult, result)
		}
	}
}

func (mock *mockAuthRequestHandler) AuthenticateRequest(req *http.Request) (user.Info, bool, error) {
	return &user.DefaultInfo{Name: "username", UID: "uid"}, true, nil
}

func (mock *mockAuthorizer) Authorize(record authorizer.Attributes) (bool, string, error) {
	return true, "", nil
}

func TestPassOAuthToken(t *testing.T) {
	req, _ := http.NewRequest("GET", "/someurl", nil)
	req.Header.Set("Authorization", "Bearer this-is-the-token")
	p := &OpenShiftProvider{}
	p.paths = recordsByPath{pathRecord{"/someurl", authorizer.AttributesRecord{}}}
	p.authenticator = &mockAuthRequestHandler{}
	p.authorizer = &mockAuthorizer{}

	session, err := p.ValidateRequest(req)
	if err != nil {
		t.Fatalf("failed to validate request %s", err.Error())
	}
	if session == nil {
		t.Fatal("failed to validate request, no session received")
	}
	if g, e := session.AccessToken, "this-is-the-token"; g != e {
		t.Errorf("access token not set in session to expected value: %v", session)
	}
}

func TestDontPassBasicAuthentication(t *testing.T) {
	req, _ := http.NewRequest("GET", "/someurl", nil)
	req.Header.Set("Authorization", "Basic dXNlcm5hbWU6cGFzc3dvcmQK")
	p := &OpenShiftProvider{}
	p.paths = recordsByPath{pathRecord{"/someurl", authorizer.AttributesRecord{}}}
	p.authenticator = &mockAuthRequestHandler{}
	p.authorizer = &mockAuthorizer{}

	session, err := p.ValidateRequest(req)
	if err != nil {
		t.Fatalf("failed to validate request %s", err.Error())
	}
	if session == nil {
		t.Fatal("failed to validate request, no session received")
	}
	if g, e := session.AccessToken, ""; g != e {
		t.Errorf("access token should be empty string for basic authentication: %v", session)
	}
}
