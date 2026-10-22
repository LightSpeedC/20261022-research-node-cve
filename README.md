# Node.js 2026年10月 セキュリティリリースの調査

2026-10-21（米国時間）に公開された 10 件の CVE の内容と、Web サーバ・CLI・Node.js 20 での影響、対処をまとめる

> 📅 作成: 2026-10-22 / 更新: 2026-10-22

[⌂](../)

Node.js の定例セキュリティリリースで、High 4 件を含む 10 件の脆弱性が修正された。本資料は、どの使い方のときに影響を受けるか（Web サーバ／HTTP クライアント／CLI）と、サポートが終了した Node.js 20 を使い続けている環境での判断材料をまとめる。

1. [概要と修正版](#1-概要と修正版)
2. [脆弱性の一覧と仕組み](#2-脆弱性の一覧と仕組み)
3. [どの使い方で影響するか（Web・CLI）](#3-どの使い方で影響するかwebcli)
4. [Node.js 20 を使っている場合](#4-nodejs-20-を使っている場合)
5. [Node.js 20 から 26 で変わること・非互換](#5-nodejs-20-から-26-で変わること非互換)
6. [対処](#6-対処)

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

## 5. Node.js 20 から 26 で変わること・非互換

20 から 26 へは 6 メジャー分（21〜26）の変更をまたぐ。公式の移行ガイドは [v20→v22](https://nodejs.org/en/blog/migrations/v20-to-v22) と [v22→v24](https://nodejs.org/en/blog/migrations/v22-to-v24) の 2 本があり、v24→v26 のガイドは見つからなかった。**まず 24 へ上げ、続けて 26 を試す**二段の移行が現実的。

### 主要な版の推移

| Node.js | V8 | NODE_MODULE_VERSION | npm | OpenSSL |
|---|---|---|---|---|
| 20.0 | 11.3 | 115 | 9.6 | 3.0 系 |
| 22.0 | 12.4 | 127 | 10.5 | 3.0 系 |
| 24.0 | 13.6 | 137 | 11.0 | 3.5 |
| 26.0 | 14.6 | 147 | 11.12 | 3.5 |

### 非互換になりやすい点

| 分類 | 変更 | 版 | 影響と対処 |
|---|---|---|---|
| ネイティブアドオン | NODE_MODULE_VERSION が 115→147。V8 の C++ API も変更。ビルドに C++20 が必要 | 毎版 | ❌ **要再ビルド** node-gyp 製の依存はすべて作り直し。prebuild の対応を確認。Node-API 製なら影響は小さい |
| TLS | OpenSSL 3.5 の既定セキュリティレベル 2。2048 bit 未満の RSA・DH 鍵、224 bit 未満の ECC 鍵、RC4 を拒否 | 24 | ❌ **接続失敗** 古い証明書の社内サーバや機器への TLS 接続が通らなくなる |
| Windows | `.bat`・`.cmd` を `spawn` で直接起動できない（CVE-2024-27980 対策） | 20 の後期・22 | ⚠️ **要修正** `shell: true` を付ける |
| Windows | 32 bit（x86）版の提供終了 | 23 | ❌ **動かない** 32 bit Windows は移行先が無い |
| モジュール | import assertions（`assert { type: 'json' }`）を削除 | 22 | ⚠️ **要修正** `with { type: 'json' }` に書き換え（20 でも動く書き方） |
| モジュール | `require()` で ESM を読める（require(esm)）が既定 | 22.12・23 | ⚠️ **挙動変化** `ERR_REQUIRE_ESM` を捕まえて分岐するコードが別の経路に入る |
| 削除された API | `crypto.createCipher`・`createDecipher` | 22 | ❌ **実行時エラー** `createCipheriv` へ |
| 削除された API | `util.isString()` 等の `util.isX()` 群・`util._extend`・`util.log` | 23 | ❌ **実行時エラー** `typeof`・`Array.isArray`・`Object.assign` へ。古い依存パッケージで踏みやすい |
| 削除された API | `tls.createSecurePair()`、`fs.Dirent.path`（→`parentPath`）、`OutgoingMessage._headers` | 24 | ❌ **実行時エラー** codemod あり |
| 削除された API | `fs.F_OK` 等（→`fs.constants.F_OK`）、`SlowBuffer`、`assert.CallTracker` | 25 | ❌ **実行時エラー** |
| 削除された API | `http.Server` の `writeHeader()`、`_stream_readable` 等の内部モジュール、`--experimental-transform-types` | 26 | ❌ **実行時エラー** 古いストリーム系の依存に注意 |
| 非推奨（警告） | `url.parse()`（実行時警告）、組み込み `punycode`、`module.register()` | 21〜26 | ⚠️ **警告** WHATWG `URL` へ |
| CLI フラグ | `--experimental-permission` → `--permission` | 24 | ⚠️ **要修正** 起動スクリプトの書き換え |
| 同梱物 | Corepack を同梱しなくなった | 25 | ⚠️ **要修正** `corepack enable` 前提の CI・Dockerfile は `npm i -g corepack` 等が必要 |
| テスト | テストランナのサブテストを自動で await。既定のレポータが `spec` | 23・24 | ⚠️ **挙動変化** `node:test` の書き方次第 |
| 出力文字列 | `util.inspect`・`assert` のメッセージ、TLS のエラーコード名の綴り修正 | 23〜26 | ⚠️ **挙動変化** 出力やエラーメッセージを文字列で比べるテストが落ちうる |
| SQLite | `node:sqlite` で外部キー制約が既定で有効、二重引用符の文字列リテラルが無効 | 23 | ⚠️ **挙動変化** |
| プラットフォーム | Linux armv7（32 bit）のバイナリ提供終了、macOS 13.5 以上 | 24 | ❌ **動かない** 古い Raspberry Pi 等 |

### 追加された機能（上げると使えるもの）

- `fetch`・Web Streams が安定（21）、`WebSocket` クライアントがフラグ不要（22）
- TypeScript の型を消して直接実行（22.18 で既定有効、24.12 で安定）。`tsconfig.json` は読まず、enum 等の型以外の構文は不可
- `node --run`（package.json の scripts 実行）、`--watch` が安定（22〜23）
- `localStorage`・`sessionStorage`（25）、`URLPattern`（24）
- 言語機能: `using`（明示的な資源管理）・`RegExp.escape`・`Float16Array`（24）、`Temporal` が既定で有効（26）

### 移行の進め方

1. `node --trace-deprecation` を付けて 20 のまま動かし、非推奨の警告を洗い出す（削除される API の多くは 20 でも警告が出る）
2. 公式の codemod（移行ガイドに記載）で機械的に書き換えられる箇所を直す
3. ネイティブアドオンの依存を洗い出す（`npm ls` で `node-gyp`・`prebuild` を使う物）
4. 24 で全テストを流す。TLS 接続先の鍵長と、Windows の `.cmd` 起動を重点的に確かめる
5. 24 で安定したら 26 を試す

> [!NOTE]
> <strong>サポート期限の資料間の食い違い。</strong>nodejs/release の表では 20 の終了は 2026-04-30。nodejs.org の過去リリースのページには別の日付が出るという報告もあった。どちらの日付でも、20 がすでにサポート外である点は変わらない。

## 6. 対処

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
