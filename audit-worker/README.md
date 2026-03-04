# melos audit worker

掲示板の投稿/削除時に、IP・UA・投稿内容を監査ログとして保存する Cloudflare Worker です。

## 1) 事前準備

- Cloudflare アカウント
- `wrangler` CLI

```bash
npm i -g wrangler
wrangler login
```

## 2) D1 作成

```bash
wrangler d1 create melos_audit
```

出力された `database_id` を `wrangler.toml` の `database_id` に貼り付けてください。

## 3) テーブル作成

```bash
wrangler d1 execute melos_audit --file=./schema.sql
```

## 4) 秘密値設定

```bash
wrangler secret put ADMIN_TOKEN
wrangler secret put IP_SALT
```

- `ADMIN_TOKEN`: 管理画面から監査ログを読むためのトークン
- `IP_SALT`: IP ハッシュ化用ソルト

## 4.5) 管理画面URL制限（既定で設定済み）

`wrangler.toml` の `vars` で、監査ログ取得APIにアクセスできる管理画面を制限しています。

- `ADMIN_ORIGIN`: `https://kimussarazu.github.io`
- `ADMIN_PATH`: `/modore-melos-game/admin.html`

`Origin + 管理画面パス + 管理トークン` が一致しないアクセスは `401` を返します。

## 5) デプロイ

```bash
wrangler deploy
```

`https://xxxx.workers.dev` が発行されます。

## 6) 管理画面へ設定

`admin.html` で以下を入力して保存:

- 監査APIベースURL: `https://xxxx.workers.dev`
- 監査管理トークン: `ADMIN_TOKEN` で設定した値

同じブラウザ内では `localStorage` に保存されます。  
`play` 側はその URL を参照して投稿/削除ログを送ります。

## API

- `POST /api/audit/log` 投稿/削除ログ受信（公開）
- `GET /api/audit/logs?limit=240&include_deleted=1` 管理ログ閲覧（`x-admin-token` 必須）
- `POST /api/audit/mark-deleted` 削除反映（`x-admin-token` 必須）
