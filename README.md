# OWASP Kansai LT — Password reset poisoning demo

Goの標準ライブラリだけで動く、ローカル検証用デモです。
サービス・攻撃者サイト・被害者の模擬メールボックスを1プロセスで起動します。
データはメモリに保存し、再起動すると初期状態に戻ります。

## 準備と起動

Go 1.22以降を使用します。追加パッケージやデータベースは不要です。

ブラウザから `.test` の名前でアクセスするため、macOSの `/etc/hosts` に次の行を追加してください。
プログラム自身はこの設定を変更しません。

```text
127.0.0.1 game.test attacker.test mail.test
```

**設定するコマンド（macOS、1回実行）：**

```sh
printf '\n127.0.0.1 game.test attacker.test mail.test\n' | sudo tee -a /etc/hosts
```

`printf` が上の行を出力し、`|` で渡した内容を `sudo tee -a` が管理者権限で `/etc/hosts` の末尾に追記します。
`\n` は改行です。3つの名前を、PC自身を指す `127.0.0.1` に対応させます。

**元に戻すコマンド（macOS）：**

```sh
sudo sed -i '' '/^127\.0\.0\.1 game\.test attacker\.test mail\.test$/d' /etc/hosts
```

上の設定コマンドで追加した行を削除します。

`.test` はテスト用に予約されたドメインです。上の設定でIPに対応させ、ポートはアプリの待ち受けで対応させます。

```sh
go run . -mode vulnerable
```

| 役割 | URL | 待ち受け |
|---|---|---|
| サービス | http://game.test:3000 | 127.0.0.1:3000 |
| 攻撃者サイト・受信ログ | http://attacker.test:3002 | 127.0.0.1:3002 |
| 模擬メールボックス | http://mail.test:3001 | 127.0.0.1:3001 |

初期アカウントは `victim@example.com`、初期パスワードは `original-pass` です。
終了は `Ctrl+C`。やり直すときは終了・再起動します。

## 通常の再設定

1. サービスのログイン画面から「パスワードを忘れた方はこちら」を開きます。
2. `victim@example.com` で申し込みます。
3. 模擬メールボックスを開きます。メールは自動表示されます。
4. `game.test:3000` を指すリンクを開き、新しいパスワードを入力・送信します。
5. 新しいパスワードでログインできます。リンクを開いただけではパスワードは変わりません。

## 攻撃デモ

アプリを再起動し、ブラウザでサービス・模擬メール・攻撃者の受信ログを開いておきます。

### 1. 細工した再設定要求を送る

```sh
curl --noproxy '*' \
  --resolve game.test:3000:127.0.0.1 \
  'http://game.test:3000/forgot-password' \
  -H 'Host: attacker.test:3002' \
  --data-urlencode 'email=victim@example.com'
```

TCPの接続先はサービスの `127.0.0.1:3000` です。HTTPのHostには `attacker.test:3002` を指定します。
`--resolve` はこのcurlだけに適用されるため、ブラウザには上記の `hosts` 設定が必要です。
送受信内容をターミナルにも表示したい場合は `-v` を追加します。

### 2. 被害者がメールのリンクを開く

模擬メールには、サービスが生成した `http://attacker.test:3002/reset?token=…` が表示されます。
被害者役としてクリックすると、別タブでエラーページが開きます。
エラーページは画面例であり、実際の攻撃に必須ではありません。

### 3. 攻撃者がトークンを使う

攻撃者の受信ログに、クリックで届いたトークンが自動表示されます。
申し込み時点では取得しておらず、メールボックスを読みに行く処理もありません。

「このトークンでサービスの再設定画面を開く」をクリックします。
受信した値を `http://game.test:3000/reset?token=…` に付ける操作補助です。

### 4. パスワードを変更してログインする

新しいパスワードに、例えば `attacker-pass` を設定します。
`victim@example.com` と新しいパスワードでログインし、成功画面を見せます。
旧パスワードと使用済みトークンは使えなくなります。

## 修正版

アプリを終了して、次のモードで再起動します。

```sh
go run . -mode fixed
```

同じ攻撃要求でも、メールのリンク先は `http://game.test:3000/reset?token=…` になります。
クリックするとサービスの再設定画面が開き、攻撃者の受信ログは空のままです。

比較するのは `main.go` の `forgotPassword` 内の処理です。

```go
baseURL := d.serviceURL // 運営側が管理する設定値
if d.mode == "vulnerable" {
    baseURL = "http://" + r.Host // 外から届いたHostを信用する
}
resetURL := baseURL + "/reset?token=" + url.QueryEscape(token)
```

修正版でもHostは拒否せず、ベースURL固定の効果を比較します。
発表では脆弱版を実演し、修正版のメールは事前に撮影してスライドで見せる想定です。

## Wireshark用の通信

macOSではループバックの `lo0` をキャプチャします。キャプチャフィルターは次です。

```text
tcp port 3000 or tcp port 3002
```

HTTPとして解析されない場合は、パケットを右クリックして **Decode As… → HTTP** を選びます。
スライド用には、以下の表示フィルターをそれぞれ使います。

**細工した申し込み：**

```text
tcp.dstport == 3000 && http.request.method == "POST" && http.request.uri == "/forgot-password"
```

TCPの宛先ポート `3000`、HTTPの `Host: attacker.test:3002`、フォームのメールアドレスを見せます。

**被害者のクリック：**

```text
tcp.dstport == 3002 && http.request.method == "GET" && http.request.uri contains "/reset?token="
```

HTTPの `GET /reset?token=…` と宛先ポート `3002` を見せます。
HTTPが分割されて見づらければ **Follow → HTTP Stream** で確認できます。
模擬メールボックスの3001番はキャプチャ対象から外れます。攻撃者画面の自動更新は表示フィルターで除外されます。

## hostsを変更せずに試す場合

```sh
go run . -mode vulnerable -base-url http://localhost:3000
```

サービスを `http://localhost:3000`、攻撃者画面を `http://localhost:3002` で開きます。
模擬メールは `http://localhost:3001` です。攻撃要求もローカル名に合わせます。

```sh
curl --noproxy '*' \
  'http://localhost:3000/forgot-password' \
  -H 'Host: localhost:3002' \
  --data-urlencode 'email=victim@example.com'
```

修正版は `-mode fixed -base-url http://localhost:3000` で起動します。
この場合はドメイン名ではなく、ポート番号の違いでリンク先の変更を見せます。

## 検証

```sh
go test -race ./...
go vet ./...
```

正常な再設定、クリック前後の漏洩、変更・ログイン、修正版での漏洩防止、トークンの期限・単回使用・再発行を確認します。

## デモの範囲と資料

メールは模擬で、外部へ送信しません。3役は1プロセスにあり、画面とポートで区別する説明用環境です。
トークンは暗号学的乱数32バイトから生成し、アカウントと10分の期限に結び付け、変更完了時に無効化します。
パスワードはメモリ内でSHA-256の値として扱います。実サービスのパスワード保存方式を再現する目的の実装ではありません。
ログイン成功画面で認証結果を示し、永続的なログインセッションやゲーム機能は実装していません。

観察のためHTTPを使います。HTTPSは通信を保護しますが、誤ったリンク先を生成する問題は解決しません。
成立条件は、未知のHostの要求が再設定処理まで届き、その値がURL生成に使われることです。

- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html#url-tokens)
- [PortSwigger Password reset poisoning](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning)
- [RFC 6761: .test](https://www.rfc-editor.org/rfc/rfc6761.html#section-6.2)
- [Wireshark: HTTPの表示フィルター](https://www.wireshark.org/docs/dfref/h/http.html)
- [Wireshark: Follow Stream](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
