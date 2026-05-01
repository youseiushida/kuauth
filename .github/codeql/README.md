# kuauth 用 CodeQL カスタムクエリ

このディレクトリには、`kuauth` ライブラリ固有の credential 取り扱い面を
保護するための静的解析クエリが置かれています。`CodeQL` ワークフロー
(`.github/workflows/codeql.yml`) で、GitHub の `security-extended` Python
スイートと並行して実行されます。

## レイアウト

共有モデル (`KuauthSources` / `KuauthSinks` / `KuauthAllowedHosts`) は
独立したライブラリパックに切り出しています。クエリパックから兄弟
ファイルとして直接 import すると CodeQL が "references a local
library, not the named module" 警告を出すため、それを回避する目的です。

ワークスペースファイル (`codeql-workspace.yml`) は `.github/codeql/`
配下ではなくリポジトリのルートに置いています。GitHub の CodeQL
Action はリポジトリルートから `codeql database init` を起動し、その
位置から workspace ファイルを探すため、それより深い位置に置くと
無視されて CI 上で「Pack X was not found locally」と落ちます (ローカル
で `codeql test run` だけ通って気づかない罠)。

```
codeql-workspace.yml         # リポジトリルート: ローカル 3 パックを列挙
.github/codeql/
  codeql-config.yml          # どのクエリを走らせるか / どのパスを scan するか
  README.md                  # このファイル
  lib/
    qlpack.yml               # ライブラリパック: kuauth/credential-leak-lib
    KuauthSources.qll        # 共有モデル: credential source
    KuauthSinks.qll          # 共有モデル: 漏洩 sink
    KuauthAllowedHosts.qll   # 共有モデル: 正規 IdP submitter (sanitizer)
  queries/
    qlpack.yml               # クエリパック: kuauth/credential-leak-queries
    codeql-suites/
      credential-leak.qls    # ローカルクエリを束ねる suite
    CredLeak-Logging.ql      # creds → logging
    CredLeak-Exception.ql    # creds → 例外メッセージ
    CredLeak-ReprStr.ql      # creds → __repr__ / __str__
    CredLeak-Disk.ql         # creds → ファイル / シリアライズ書き出し
    CredLeak-UnknownHttp.ql  # creds → 非 IdP への HTTP 送信
    tests/
      qlpack.yml             # テストパック (lib + queries に依存)
      <QueryName>/
        test.py              # extractor への入力
        <QueryName>.qlref    # 対象クエリへの参照
        <QueryName>.expected # 期待出力 (`--learn` で再生成)
```

## Source / Sink / Sanitizer

### Source (`lib/KuauthSources.qll`)

credential を保持する値:

- `KyotoUAuth.password` (property) と `_password` (attribute)
- `KyotoUAuth._totp_secret`
- `KyotoUAuth._onetime_password`
- `KyotoUAuth._resolve_otp()` の戻り値
- `KyotoUAuth._otp_callback` を呼び出した結果

`username` は意図的に source から外しています。EPPN として URL
解決可能な形で IdP 側にも共有される値であり、taint 扱いすると精度
が落ちるだけで保護増分がほぼないからです。`__init__` の引数も
直接モデル化していません。実際に sink へ流れるパスはすべて構築
後の `self._password` 等の attribute read を経由するので、
attribute source 側でカバーできます。

### Sink (`lib/KuauthSinks.qll`)

- Logging: `logging.*`, `Logger.*` (API graph で型付け), `print`,
  `warnings.warn`, `sys.stdout/stderr.write`, `traceback.print_*`。
  `logger.<level>(msg, *args)` の場合、引数 0 はテンプレート、
  引数 1 以降は `%` 置換で行に展開されるので、すべての positional
  引数を sink にしています。
- Exception: `raise X(...)` の引数
- ReprStr: `__repr__` / `__str__` の戻り値
- Disk: `open().write`, `Path.write_text/write_bytes`,
  `json.dump(s)`, `pickle.dump(s)`, `csv.writer.writerow(s)`,
  `csv.DictWriter.writerow(s)`
- HTTP: 任意の `.get/post/put/patch/delete/request/send/stream(...)`
  メソッド呼び出し、または `httpx.<method>(...)` の module-level
  shortcut。受信側の型は絞っていません。httpx は third-party で
  CodeQL の API graph では `KyotoUAuth._http = httpx.Client()` →
  `_SPService.http` プロパティ → `self.http.post(...)` の経路を
  end-to-end で追えないためです。代わりに「メソッド名 + httpx
  特有の引数形状 (positional URL もしくは `params`/`data`/`json`/
  `headers`/`content` の kwarg)」で識別しているので、`dict.get` /
  `list.append` のような同名呼び出しが sink まで到達しません。
  `request` / `stream` だけ位置引数の順序が違う (引数 0 = HTTP verb、
  引数 1 = URL) ので別の枝でモデル化しています。

### Sanitizer (`lib/KuauthAllowedHosts.qll`)

正規の認証フォーム送信を行う 4 つの関数:

- `_submit_simplesaml_password`
- `_submit_simplesaml_otp`
- `_submit_shib_idp_login`
- `PandA._submit_cas_login` (クラス名ピン留め)

囲んでいる関数がこのアロウリストに該当する場合は、
`CredLeak-UnknownHttp` の sink から外す扱いになります。5 つ目の
IdP submitter を足すときは、ここを編集することが意図的な手順に
なっています。「無言でアロウリストが膨らんで気づかない」より
「足し忘れて CI が騒ぐ」失敗モードのほうが credential を扱う
ライブラリには望ましいためです。

## ローカル実行

CodeQL CLI
(<https://github.com/github/codeql-cli-binaries/releases>) を
インストールし、`codeql` が `PATH` 上にあることを確認してください。

```bash
# 3 つのローカルパックの依存解決。
codeql pack install .github/codeql/lib
codeql pack install .github/codeql/queries
codeql pack install .github/codeql/queries/tests

# kuauth のソースツリーから database を作る。
codeql database create --language=python --source-root=. ./codeql-db

# ローカルパックを database に対して走らせる。
codeql database analyze ./codeql-db \
  --format=sarif-latest \
  --output=results.sarif \
  .github/codeql/queries
```

## 期待出力 (`.expected`) の更新

クエリの出力フォーマットが変わるたびに `tests/<QueryName>/` 配下の
`.expected` を再生成します。

```bash
# リポジトリのルートで:
codeql test run --learn .github/codeql/queries/tests/

# 確認後にコミット。
codeql test run .github/codeql/queries/tests/   # actual と一致するか検証
```

`--learn` を初めて回すと、`.expected` に実際のクエリ出力が書き出され
ます。コミット前に内容を確認し、positive ケース (`leak_*`) が確かに
flag されていて、negative ケース (`safe_*`) が flag されていないこと
を目視で押さえてからコミットしてください。

## 新しいクエリを追加するとき

1. `queries/` 配下に `<QueryName>.ql` と `<QueryName>.qhelp` を追加。
   新しい source / sink / sanitizer が要るなら、まず `lib/*.qll` を
   先に更新する。
2. `tests/<QueryName>/` ディレクトリを作り、positive と negative の
   両ケースを含む `test.py` と `<QueryName>.qlref` を置く。
3. `codeql test run --learn .github/codeql/queries/tests/` を回し、
   `.expected` を生成。
4. これら 4 ファイルをまとめて 1 つのコミットにする。

## Surface invariant test

QL テストフィクスチャは `KyotoUAuth` の合成 stand-in を使っています。
`codeql test run` で `src/kuauth` ツリー全体を取り込まずに済ませる
ためですが、その代償として `src/kuauth/auth.py` で `_password` を
`_pw` にリネームしても QL テストは緑のままになるという穴が空きます。

これを塞ぐのが `tests/unit/test_codeql_query_surface.py` です。
クエリが依存している attribute / method 名をここで pin しているので、
`src/` 側でリネームすると pytest が先に落ちます。これにより
「リネームを `KuauthSources.qll` / `KuauthAllowedHosts.qll` の更新と
QL ベースライン再生成と同じ change で揃える」ことが強制されます。

通常の `uv run pytest tests/unit -q` で動くので、CodeQL CLI は不要です。
