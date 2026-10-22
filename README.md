# Node.js 2026年10月 セキュリティリリースの調査

2026-10-21（米国時間）に公開された 10 件の CVE の内容と、Web サーバ・CLI・Node.js 20 での影響、対処をまとめる

> 📅 作成: 2026-10-22 / 更新: 2026-10-22

[⌂](../)

Node.js の定例セキュリティリリースで、High 4 件を含む 10 件の脆弱性が修正された。本資料は、どの使い方のときに影響を受けるか（Web サーバ／HTTP クライアント／CLI）と、サポートが終了した Node.js 20 を使い続けている環境での判断材料をまとめる。

1. [概要と修正版](#1-概要と修正版)
2. [脆弱性の一覧と仕組み](#2-脆弱性の一覧と仕組み)
3. [どの使い方で影響するか（Web・CLI）](#3-どの使い方で影響するかwebcli)
4. [Node.js 20 を使っている場合](#4-nodejs-20-を使っている場合)
5. [対処](#5-対処)

## 1. 概要と修正版

| 系列 | 状態 | サポート終了 | 修正版 |
|---|---|---|---|
| 26.x | Current | 2029-04-30 | ✅ **修正** v26.12.1 |
| 24.x | Active LTS | 2028-04-30 | ✅ **修正** v24.22.1 |
| 22.x | Maintenance LTS | 2027-04-30 | ✅ **修正** v22.23.4 |
| 20.x | End-of-Life | 2026-04-30 | ❌ **修正なし** |

同梱の依存物も更新された。c-ares・Undici（全系列）、OpenSSL（24.x・22.x）、SQLite（22.x）、CA 証明書（侵害された eMudhra 中間 CA の除去。全系列）。

公式発表には回避策の記載が無く、対処は修正版への更新のみとされている。

## 2. 脆弱性の一覧と仕組み

| CVE | 深刻度 | 対象系列 | 内容 | 影響する側 |
|---|---|---|---|---|
| CVE-2026-111497 | ❌ **High** | 26 / 24 / 22 | Brotli デコーダの境界外書き込み。リモートコード実行のおそれ | 信頼できない Brotli データを展開する側 |
| CVE-2026-105483 | ❌ **High** | 26 / 24 | 全角数字で書いた IP で TLS のホスト名検証を回避（回帰バグ） | TLS クライアント |
| CVE-2026-106069 | ❌ **High** | 26 / 24 / 22 | 正規化で IP に化けるホスト名で TLS のホスト名検証を回避 | TLS クライアント |
| CVE-2026-105482 | ❌ **High** | 26 / 24 / 22 | `dns.resolve*` が NUL 文字以降を切り捨てる | 外部入力を名前解決する側 |
| CVE-2026-105481 | ⚠️ **Medium** | 26 / 24 / 22 | keep-alive のソケットが、要求を送る前に届いた応答を処理する | HTTP クライアント |
| CVE-2026-106072 | ⚠️ **Medium** | 26 / 24 / 22 | 非正規の IPv4 表記で、証明書の DNS 名が IP の接続先を認証する | TLS クライアント |
| CVE-2026-106074 | ⚠️ **Medium** | 26 / 24 / 22 | `randomUUID()`・`randomInt()` の乱数キャッシュが snapshot・SEA に焼き込まれ、全プロセスで同じ値になる | snapshot・SEA で配る CLI / サーバ |
| CVE-2026-106070 | ⬜ **Low** | 26 | `ZipFile` がヘッダ検証失敗後に攻撃者の制御するバイト列を返す | ZIP を読む側 |
| CVE-2026-106071 | ⬜ **Low** | 26 | Permission Model のワイルドカードで、ファイルの許可が広がりすぎる | `--permission` 利用時 |
| CVE-2026-106073 | ⬜ **Low** | 26 / 24 / 22 | `fs.realpathSync` で Permission Model を回避 | `--permission` 利用時 |

### High 4 件の仕組み

#### CVE-2026-111497（Brotli）

不正な Brotli データの展開中に境界外書き込みが起きる。修正は Google の Brotli 本家のコミットの取り込みで、ブロック種別が 1 つしか宣言されていないストリームにブロック切り替えが現れたら即座に失敗させる。到達する API は `zlib.brotliDecompress()`・`brotliDecompressSync()`・`createBrotliDecompress()` と、応答の `Content-Encoding: br` を自動で展開する `fetch()`（Undici）。

> [!NOTE]
> <strong>fetch は要求していなくても展開する。</strong>クライアントが `Accept-Encoding: identity` を送っても、悪意あるサーバが `br` で返せばデコーダが動く。

Debian・Ubuntu のパッケージで入れた Node.js はシステムの libbrotli を使うことがあり、その場合の修正は libbrotli パッケージ側から来る。

#### CVE-2026-105483・CVE-2026-106069（TLS のホスト名検証）

`tls.checkServerIdentity()` が、IP の形をした接続先を、証明書の `IP Address:` ではなく `DNS:` 項目と照合してしまう。例: `0127.0.0.1` は `url.domainToASCII()` では 8 進として `87.0.0.1` と解釈されるが、OS は `127.0.0.1` へ接続する。`DNS:87.0.0.1` の証明書で、別のマシンが本物として通ってしまう。

悪用には、クライアントが信頼する CA から IP の形をした `DNS:` 項目を持つ証明書を得る必要があり、条件は厳しい。接続先のホスト名を外部入力で決めるクライアントで問題になる。

#### CVE-2026-105482（dns.resolve）

c-ares が NUL を文字列の終わりとして扱う。`'example.com\0.trusted.corp'` を検査では `.trusted.corp` と見て許可しても、実際に問い合わせるのは `example.com` になる。`dns.lookup()`（OS のリゾルバ）は対象外で、`dns.resolve*()`・`dns.reverse()` が対象。

## 3. どの使い方で影響するか（Web・CLI）

今回の High は、多くが <strong>Node.js が外へ通信するとき（クライアント側）</strong>の問題である。「Web サーバか CLI か」より、**信頼できない相手のデータを受け取るか**で判断する。

| 使い方 | 影響する CVE | 危険度の目安 |
|---|---|---|
| Web サーバ（Express 等）で、要求本文の `Content-Encoding: br` を展開する | 111497 | ❌ **高** 外部から未認証で到達しうる |
| Web サーバが外部 API・利用者指定の URL へ `fetch` する（Webhook・プロキシ・OGP 取得・SSRF になりうる処理） | 111497・105481・TLS 3 件 | ❌ **高** 接続先を利用者が選べるなら特に |
| Web サーバが静的配信・API 応答だけ（圧縮は送るだけ、外へ通信しない） | ほぼ無し | ✅ **低** 圧縮して**送る**側は対象外 |
| CLI がインターネットからダウンロードする（npm 系ツール・更新確認・スクレイピング） | 111497・TLS 3 件 | ⚠️ **中** 接続先が改ざん・なりすましされた場合 |
| CLI が手元のファイルだけを扱う（ビルド・変換・lint） | ほぼ無し | ✅ **低** 外部の Brotli・ZIP を読まない限り |
| CLI・サーバを SEA や startup snapshot で配布している | 106074 | ⚠️ **中** UUID・トークンが全プロセスで重複する |
| 利用者入力のホスト名を `dns.resolve*` で検査する | 105482 | ⚠️ **中** 許可リストのすり抜け |
| `--permission` で権限を絞って動かす | 106071・106073 | ⬜ **低** Low |

> [!NOTE]
> <strong>Web で使うかどうかより、外へ通信するかが効く。</strong>静的なサイトを返すだけのサーバより、外部 URL を取りに行く CLI のほうが今回の High に当たりやすい。

## 4. Node.js 20 を使っている場合

Node.js 20 は 2026-04-30 にサポートが終了した。公式は終了した系列を検証しないため、**影響するかどうかの公式の判定は無く、修正版も出ない**。

| CVE | Node.js 20 での見込み（未検証の推定） |
|---|---|
| 111497（Brotli） | ❌ **影響ありと見るべき** 同じ Brotli ライブラリを同梱しており、修正は本家のコミット。20 にだけ欠陥が無い根拠は無い |
| 106069・106072・105482・105481 | ❌ **影響ありと見るべき** 22 以降の全系列に共通する処理で、22 より古い 20 に入っていない根拠が無い |
| 105483（全角数字） | ⚠️ **影響しない可能性** 24・26 に入った回帰のため。ただし未確認 |
| 106074（SEA・snapshot） | ⚠️ **使っていれば要確認** 20 では SEA が実験的機能 |

加えて、20 は 2026-04-30 以降に公開された過去の脆弱性（2026 年 6 月・7 月のリリース分）も修正されていない。今回だけを見て「当たらない」と判断しても、未修正の穴は積み上がっている。

> [!NOTE]
> <strong>20 のまま安全にする方法は無い。</strong>22 は 2027-04-30 で終わるため、移るなら 24（2028-04-30 まで）を勧める。

## 5. 対処

### 優先順位

1. **外部と通信するサーバ・ツールから上げる**。Brotli を展開する Web サーバ、`fetch` で外部へ取りに行く処理
2. **Node.js 20 の環境は 24 へ移す**。移すまでの間は、下の暫定策で露出を減らす
3. **SEA・snapshot で配っている物は、更新した Node.js で作り直す**。実行環境の Node だけを上げても直らない
4. **Node.js を内蔵する物を確かめる**。Docker のベースイメージ（`node:20` 等のタグを固定していないか）、Electron、CI のランナ、ディストリのパッケージ（libbrotli も）

### 移行までの暫定策（恒久対策ではない）

- 受け取る要求の `Content-Encoding: br` を前段（リバースプロキシ等）で拒否する
- 外部へ `fetch` する処理は、接続先を許可リストに限る
- 利用者入力のホスト名は、NUL を含むもの・非正規の IP 表記を拒否する

```javascript
const net = require('node:net');
const url = require('node:url');

// 非正規の IP 表記（0127.0.0.1 など）を拒否する
function isNonCanonicalIP(host) {
	return !net.isIP(host) && net.isIP(url.domainToASCII(host)) !== 0;
}
```

### 版の確認

```shell
node -v
node -p "process.versions.brotli + ' / ' + process.versions.openssl"
```

### 出典

- [Node.js — Wednesday, October 21, 2026 Security Releases](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- [nodejs/release — Release schedule](https://github.com/nodejs/release#release-schedule)
- [Node.js v24.22.1 fixes four HIGH CVEs, tested against v24.22.0 and EOL v25.3.0](https://lilting.ch/en/articles/nodejs-tls-dns-brotli-security-release)
- [Vercel — Node.js security advisory: Brotli decoder RCE](https://vercel.com/kb/bulletin/node-js-security-advisory)
- [Wardio — Node.js Brotli RCE CVE-2026-111497: what to update](https://wardio.net/guides/nodejs-brotli-cve-2026-111497/)
- [Cyber Security News — Node.js Releases Security Updates](https://cybersecuritynews.com/node-js-releases-security-updates/)

[⌂](../)
