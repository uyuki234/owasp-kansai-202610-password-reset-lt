package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	victimEmail        = "victim@example.com"
	initialPassword    = "original-pass"
	defaultServiceURL  = "http://game.test:3000"
	defaultAttackerURL = "http://attacker.test:3002"
	defaultMailboxURL  = "http://mail.test:3001"
)

//go:embed web/*
var webFiles embed.FS

var pageTemplate = template.Must(template.ParseFS(webFiles, "web/page.html"))

type resetToken struct {
	Email   string
	Expires time.Time
}

type mailMessage struct {
	To     string
	URL    string
	SentAt string
}

type capturedRequest struct {
	Token      string
	Path       string
	ReceivedAt string
}

type demo struct {
	mode        string
	serviceURL  string
	attackerURL string
	mailboxURL  string
	mu          sync.Mutex
	password    [32]byte
	tokens      map[string]resetToken
	mail        *mailMessage
	capture     *capturedRequest
}

type page struct {
	Kind        string
	Title       string
	Error       string
	Email       string
	Token       string
	ServiceURL  string
	AttackerURL string
	MailboxURL  string
	ResetURL    string
	Mail        *mailMessage
	Capture     *capturedRequest
}

func newDemo(mode, serviceURL string) *demo {
	return &demo{
		mode:        mode,
		serviceURL:  serviceURL,
		attackerURL: defaultAttackerURL,
		mailboxURL:  defaultMailboxURL,
		password:    sha256.Sum256([]byte(initialPassword)),
		tokens:      make(map[string]resetToken),
	}
}

func displayTime() string {
	return time.Now().In(time.FixedZone("JST", 9*60*60)).Format("15:04:05")
}

func (d *demo) render(w http.ResponseWriter, status int, p page) {
	p.ServiceURL, p.AttackerURL, p.MailboxURL = d.serviceURL, d.attackerURL, d.mailboxURL
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := pageTemplate.Execute(w, p); err != nil {
		log.Printf("画面の描画に失敗: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("JSONの書き込みに失敗: %v", err)
	}
}

func addAssets(mux *http.ServeMux) {
	assets, err := fs.Sub(webFiles, "web")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assets))))
}

func (d *demo) serviceHandler() http.Handler {
	mux := http.NewServeMux()
	addAssets(mux)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		d.render(w, http.StatusOK, page{Kind: "login", Title: "ログイン", Email: victimEmail})
	})
	mux.HandleFunc("POST /login", d.login)
	mux.HandleFunc("GET /forgot-password", func(w http.ResponseWriter, r *http.Request) {
		d.render(w, http.StatusOK, page{Kind: "forgot", Title: "パスワードを再設定", Email: victimEmail})
	})
	mux.HandleFunc("POST /forgot-password", d.forgotPassword)
	mux.HandleFunc("GET /reset", d.resetForm)
	mux.HandleFunc("POST /reset", d.resetPassword)
	return mux
}

func (d *demo) forgotPassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "入力を読み取れませんでした", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(r.PostForm.Get("email")) == victimEmail {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			http.Error(w, "トークンを生成できませんでした", http.StatusInternalServerError)
			return
		}
		token := hex.EncodeToString(secret)

		// 比較するのは、このベースURLの生成方法だけ。
		baseURL := d.serviceURL
		if d.mode == "vulnerable" {
			// 意図した脆弱性: 外部から届いたHostをメールのリンク先として信用する。
			baseURL = "http://" + r.Host
		}
		resetURL := baseURL + "/reset?token=" + url.QueryEscape(token)

		d.mu.Lock()
		d.tokens = map[string]resetToken{token: {Email: victimEmail, Expires: time.Now().Add(10 * time.Minute)}}
		d.mail = &mailMessage{To: victimEmail, URL: resetURL, SentAt: displayTime()}
		d.mu.Unlock()
	}
	// トークンは申し込み元へ返さず、登録済みアカウントの模擬メールだけに送る。
	d.render(w, http.StatusOK, page{Kind: "sent", Title: "メールを確認してください"})
}

func (d *demo) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "入力を読み取れませんでした", http.StatusBadRequest)
		return
	}
	d.mu.Lock()
	ok := r.PostForm.Get("email") == victimEmail && sha256.Sum256([]byte(r.PostForm.Get("password"))) == d.password
	d.mu.Unlock()
	if !ok {
		d.render(w, http.StatusUnauthorized, page{Kind: "login", Title: "ログイン", Email: r.PostForm.Get("email"), Error: "メールアドレスまたはパスワードが違います。"})
		return
	}
	d.render(w, http.StatusOK, page{Kind: "logged-in", Title: "ログイン成功", Email: victimEmail})
}

func (d *demo) validToken(token string) bool {
	t, ok := d.tokens[token]
	return ok && time.Now().Before(t.Expires)
}

func (d *demo) resetForm(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	d.mu.Lock()
	ok := d.validToken(token)
	d.mu.Unlock()
	if !ok {
		d.render(w, http.StatusBadRequest, page{Kind: "invalid", Title: "リンクを利用できません"})
		return
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	d.render(w, http.StatusOK, page{Kind: "reset", Title: "新しいパスワードを設定", Token: token})
}

func (d *demo) resetPassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "入力を読み取れませんでした", http.StatusBadRequest)
		return
	}
	token, password := r.PostForm.Get("token"), r.PostForm.Get("password")
	d.mu.Lock()
	if !d.validToken(token) {
		d.mu.Unlock()
		d.render(w, http.StatusBadRequest, page{Kind: "invalid", Title: "リンクを利用できません"})
		return
	}
	if password == "" {
		d.mu.Unlock()
		d.render(w, http.StatusBadRequest, page{Kind: "reset", Title: "新しいパスワードを設定", Token: token, Error: "新しいパスワードを入力してください。"})
		return
	}
	d.password = sha256.Sum256([]byte(password))
	delete(d.tokens, token)
	d.mu.Unlock()
	d.render(w, http.StatusOK, page{Kind: "changed", Title: "パスワードを変更しました"})
}

func (d *demo) mailboxHandler() http.Handler {
	mux := http.NewServeMux()
	addAssets(mux)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		mail := d.mail
		d.mu.Unlock()
		d.render(w, http.StatusOK, page{Kind: "mailbox", Title: "受信トレイ", Mail: mail})
	})
	mux.HandleFunc("GET /api/mail", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		mail := d.mail
		d.mu.Unlock()
		writeJSON(w, mail)
	})
	return mux
}

func (d *demo) attackerHandler() http.Handler {
	mux := http.NewServeMux()
	addAssets(mux)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		capture := d.capture
		d.mu.Unlock()
		p := page{Kind: "attacker", Title: "トークン受信ログ", Capture: capture}
		if capture != nil {
			p.ResetURL = d.serviceURL + "/reset?token=" + url.QueryEscape(capture.Token)
		}
		d.render(w, http.StatusOK, p)
	})
	mux.HandleFunc("GET /reset", func(w http.ResponseWriter, r *http.Request) {
		if token := r.URL.Query().Get("token"); token != "" {
			capture := &capturedRequest{Token: token, Path: r.URL.RequestURI(), ReceivedAt: displayTime()}
			d.mu.Lock()
			d.capture = capture
			d.mu.Unlock()
			log.Printf("攻撃者サイト: /resetへのアクセスを受信（トークンあり）")
		}
		d.render(w, http.StatusNotFound, page{Kind: "decoy", Title: "ページを表示できません"})
	})
	mux.HandleFunc("GET /api/capture", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		capture := d.capture
		d.mu.Unlock()
		var resetURL string
		if capture != nil {
			resetURL = d.serviceURL + "/reset?token=" + url.QueryEscape(capture.Token)
		}
		writeJSON(w, map[string]any{"capture": capture, "resetURL": resetURL})
	})
	return mux
}

func main() {
	mode := flag.String("mode", "vulnerable", "vulnerable または fixed")
	baseURL := flag.String("base-url", defaultServiceURL, "運営側が管理するサービスのベースURL")
	flag.Parse()
	if *mode != "vulnerable" && *mode != "fixed" {
		log.Fatal("-mode は vulnerable または fixed を指定してください")
	}
	parsed, err := url.Parse(*baseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		log.Fatal("-base-url は http(s)://ホスト:ポート の形式で指定してください")
	}
	d := newDemo(*mode, strings.TrimRight(*baseURL, "/"))
	targets := []struct {
		address string
		handler http.Handler
	}{
		{"127.0.0.1:3000", d.serviceHandler()},
		{"127.0.0.1:3002", d.attackerHandler()},
		{"127.0.0.1:3001", d.mailboxHandler()},
	}
	var listeners []net.Listener
	for _, target := range targets {
		listener, err := net.Listen("tcp", target.address)
		if err != nil {
			for _, opened := range listeners {
				opened.Close()
			}
			log.Fatalf("%sで待ち受けできません: %v", target.address, err)
		}
		listeners = append(listeners, listener)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errors := make(chan error, len(targets))
	var servers []*http.Server
	for i, target := range targets {
		server := &http.Server{Handler: target.handler, ReadHeaderTimeout: 5 * time.Second}
		servers = append(servers, server)
		go func(listener net.Listener) { errors <- server.Serve(listener) }(listeners[i])
	}
	fmt.Printf("\nPassword reset poisoning demo [%s]\n", *mode)
	fmt.Printf("サービス       %s\n攻撃者サイト   %s\n模擬メール     %s\n", d.serviceURL, d.attackerURL, d.mailboxURL)
	fmt.Printf("アカウント     %s\n初期パスワード %s\n\nCtrl+Cで終了。再起動で初期状態に戻ります。\n", victimEmail, initialPassword)
	select {
	case <-ctx.Done():
	case err := <-errors:
		if err != nil && err != http.ErrServerClosed {
			log.Printf("サーバーのエラー: %v", err)
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, server := range servers {
		server.Shutdown(shutdownCtx)
	}
}
