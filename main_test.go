package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type testRig struct {
	demo                       *demo
	service, attacker, mailbox *httptest.Server
}

func startRig(t *testing.T, mode string) testRig {
	t.Helper()
	d := newDemo(mode, defaultServiceURL)
	rig := testRig{demo: d}
	rig.service = httptest.NewServer(d.serviceHandler())
	rig.attacker = httptest.NewServer(d.attackerHandler())
	rig.mailbox = httptest.NewServer(d.mailboxHandler())
	d.serviceURL, d.attackerURL, d.mailboxURL = rig.service.URL, rig.attacker.URL, rig.mailbox.URL
	t.Cleanup(rig.service.Close)
	t.Cleanup(rig.attacker.Close)
	t.Cleanup(rig.mailbox.Close)
	return rig
}

func responseBody(t *testing.T, response *http.Response, err error, status int) string {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != status {
		t.Fatalf("status = %d, want %d; body: %s", response.StatusCode, status, body)
	}
	return string(body)
}

func get(t *testing.T, target string, status int) string {
	t.Helper()
	response, err := http.Get(target)
	return responseBody(t, response, err, status)
}

func post(t *testing.T, target string, values url.Values, status int) string {
	t.Helper()
	response, err := http.PostForm(target, values)
	return responseBody(t, response, err, status)
}

func (rig testRig) mail(t *testing.T) *mailMessage {
	t.Helper()
	var mail *mailMessage
	if err := json.Unmarshal([]byte(get(t, rig.mailbox.URL+"/api/mail", http.StatusOK)), &mail); err != nil {
		t.Fatal(err)
	}
	return mail
}

func (rig testRig) capture(t *testing.T) (*capturedRequest, string) {
	t.Helper()
	var result struct {
		Capture  *capturedRequest
		ResetURL string
	}
	if err := json.Unmarshal([]byte(get(t, rig.attacker.URL+"/api/capture", http.StatusOK)), &result); err != nil {
		t.Fatal(err)
	}
	return result.Capture, result.ResetURL
}

func (rig testRig) requestReset(t *testing.T, host string) string {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, rig.service.URL+"/forgot-password", strings.NewReader(url.Values{"email": {victimEmail}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = host
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := http.DefaultClient.Do(request)
	return responseBody(t, response, err, http.StatusOK)
}

func hostOf(t *testing.T, target string) string {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func tokenOf(t *testing.T, target string) string {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	token := u.Query().Get("token")
	if len(token) != 64 {
		t.Fatalf("unexpected token: %q", token)
	}
	return token
}

func TestPasswordResetFlow(t *testing.T) {
	for _, scenario := range []struct {
		name, mode string
		poisoned   bool
	}{
		{"normal", "vulnerable", false},
		{"poisoned", "vulnerable", true},
		{"fixed", "fixed", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			rig := startRig(t, scenario.mode)
			if rig.mail(t) != nil {
				t.Fatal("mail exists before request")
			}
			if capture, _ := rig.capture(t); capture != nil {
				t.Fatal("attacker knows token before request")
			}
			host := hostOf(t, rig.service.URL)
			if scenario.poisoned {
				host = hostOf(t, rig.attacker.URL)
			}
			requestBody := rig.requestReset(t, host)
			mail := rig.mail(t)
			if mail == nil || mail.To != victimEmail {
				t.Fatal("mail was not sent to victim")
			}
			token := tokenOf(t, mail.URL)
			if strings.Contains(requestBody, token) {
				t.Fatal("token leaked in request response")
			}
			if capture, _ := rig.capture(t); capture != nil {
				t.Fatal("attacker knows token before victim click")
			}
			wantBase := rig.service.URL
			if scenario.poisoned && scenario.mode == "vulnerable" {
				wantBase = rig.attacker.URL
			}
			if !strings.HasPrefix(mail.URL, wantBase+"/reset?") {
				t.Fatalf("wrong mail URL: %s", mail.URL)
			}
			status := http.StatusOK
			if wantBase == rig.attacker.URL {
				status = http.StatusNotFound
			}
			get(t, mail.URL, status)
			// URLを開くだけでパスワードは変わらない。
			post(t, rig.service.URL+"/login", url.Values{"email": {victimEmail}, "password": {initialPassword}}, http.StatusOK)
			capture, resetURL := rig.capture(t)
			if wantBase == rig.attacker.URL {
				if capture == nil || capture.Token != token {
					t.Fatal("victim click did not leak the token")
				}
				if resetURL != rig.service.URL+"/reset?token="+token {
					t.Fatalf("wrong helper URL: %s", resetURL)
				}
				get(t, resetURL, http.StatusOK)
			} else if capture != nil {
				t.Fatal("token leaked in normal or fixed mode")
			}
			post(t, rig.service.URL+"/reset", url.Values{"token": {token}, "password": {"attacker-pass"}}, http.StatusOK)
			body := post(t, rig.service.URL+"/login", url.Values{"email": {victimEmail}, "password": {"attacker-pass"}}, http.StatusOK)
			if !strings.Contains(body, victimEmail) || !strings.Contains(body, "ログイン成功") {
				t.Fatal("account login was not shown")
			}
			post(t, rig.service.URL+"/login", url.Values{"email": {victimEmail}, "password": {initialPassword}}, http.StatusUnauthorized)
			post(t, rig.service.URL+"/reset", url.Values{"token": {token}, "password": {"reuse-pass"}}, http.StatusBadRequest)
			get(t, rig.service.URL+"/reset?token="+token, http.StatusBadRequest)
		})
	}
}

func TestInvalidTokensCannotChangePassword(t *testing.T) {
	rig := startRig(t, "vulnerable")
	post(t, rig.service.URL+"/reset", url.Values{"token": {"unknown"}, "password": {"changed"}}, http.StatusBadRequest)
	rig.requestReset(t, hostOf(t, rig.service.URL))
	first := tokenOf(t, rig.mail(t).URL)
	rig.requestReset(t, hostOf(t, rig.service.URL))
	second := tokenOf(t, rig.mail(t).URL)
	if first == second {
		t.Fatal("token was not regenerated")
	}
	post(t, rig.service.URL+"/reset", url.Values{"token": {first}, "password": {"changed"}}, http.StatusBadRequest)
	rig.demo.mu.Lock()
	token := rig.demo.tokens[second]
	token.Expires = time.Now().Add(-time.Second)
	rig.demo.tokens[second] = token
	rig.demo.mu.Unlock()
	get(t, rig.service.URL+"/reset?token="+second, http.StatusBadRequest)
	post(t, rig.service.URL+"/reset", url.Values{"token": {second}, "password": {"changed"}}, http.StatusBadRequest)
	post(t, rig.service.URL+"/login", url.Values{"email": {victimEmail}, "password": {initialPassword}}, http.StatusOK)
}
