package openshift

import (
	"reflect"
	"testing"
)

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
