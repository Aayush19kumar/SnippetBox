package main

import (
	asserts "aayush/internal/assert"
	"gopkg.in/go-playground/assert.v1"
	"net/http"
	"testing"
)

func TestSnippetCreate(t *testing.T) {
	app := newTestApplication(t)
	ts := newTestServer(t, app.routes())
	defer ts.Close()
	t.Run("Unauthenticated", func(t *testing.T) {
		code, headers, _ := ts.get(t, "/snippet/create")
		assert.Equal(t, code, http.StatusSeeOther)
		assert.Equal(t, headers.Get("Location"), "/user/login")
	})
}
func TestPing(t *testing.T) {

	app := newTestApplication(t)
	ts := newTestServer(t, app.routes())
	defer ts.Close()
	code, _, body := ts.get(t, "/ping")
	assert.Equal(t, code, http.StatusOK)
	assert.Equal(t, body, "OK")
}
func TestSnippetView(t *testing.T) {
	app := newTestApplication(t)
	ts := newTestServer(t, app.routes())
	defer ts.Close()
	tests := []struct {
		name     string
		urlPath  string
		wantCode int
		wantBody string
	}{
		{
			name:     "Valid ID",
			urlPath:  "/snippet/view/1",
			wantCode: http.StatusOK,
			wantBody: "An old silent pond...",
		},
		{
			name:     "Non-existent ID",
			urlPath:  "/snippet/view/2",
			wantCode: http.StatusNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, body := ts.get(t, tt.urlPath)
			assert.Equal(t, code, tt.wantCode)
			if tt.wantBody != "" {
				asserts.StringContains(t, body, tt.wantBody)
			}
		})
	}

}
