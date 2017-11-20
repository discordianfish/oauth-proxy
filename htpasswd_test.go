package main

import (
	"bytes"
	"github.com/bmizerany/assert"
	"testing"
)

func TestHtpasswd(t *testing.T) {
	file := bytes.NewBuffer([]byte("testuser:{SHA}PaVBVZkYqAjCQCu6UBL2xgsnZhw=\nfoo:{SHA}rjXz/gOeuoMRiEa7Get6eHtKkX0=\n"))
	h, err := NewHtpasswd(file)
	assert.Equal(t, err, nil)

	valid := h.Validate("testuser", "asdf")
	assert.Equal(t, valid, true)
	valid = h.Validate("foo", "asdf")
	assert.Equal(t, valid, false)
	valid = h.Validate("foo", "ghjk")
	assert.Equal(t, valid, true)
	valid = h.Validate("nobody", "ghjk")
	assert.Equal(t, valid, false)
}
