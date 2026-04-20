# kuauth

[![PyPI version](https://img.shields.io/pypi/v/kuauth.svg)](https://pypi.org/project/kuauth/)
[![Python](https://img.shields.io/pypi/pyversions/kuauth.svg)](https://pypi.org/project/kuauth/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Live integration](https://github.com/youseiushida/kuauth/actions/workflows/live-integration.yml/badge.svg?event=schedule)](https://github.com/youseiushida/kuauth/actions/workflows/live-integration.yml)
[![Context7 Indexed](https://img.shields.io/badge/Context7-Indexed-047857)](https://context7.com/youseiushida/kuauth)
[![Context7 llms.txt](https://img.shields.io/badge/Context7-llms.txt-047857)](https://context7.com/youseiushida/kuauth/llms.txt)

京都大学の SSO (KULASIS / KULMS / MyKULINE / PandA) を単一のセッションで叩くための Python クライアントです。初回の `get()` / `post()` 時に必要な IdP ウォークが遅延実行され、それ以降は通常の HTTP クライアントとして使えます。

## インストール

```bash
uv add kuauth
```

## Quickstart

```python
from kuauth import KyotoUAuth, KULASIS, KULMS, MyKULINE, PandA

auth = KyotoUAuth(
    username="a0XXXXXX",
    password="your-password",
    # onetime_password="424242",             # 手元の 6 桁コードを 1 回だけ使う
    otp_callback=lambda: input("OTP: "),     # 対話的スクリプト
    # totp_secret="JBSWY3DPEHPK3PXP",        # cron / CI など無人実行
)

print(KULASIS(auth).get("/student/u/t/top").text)           # 教務 (Shift_JIS 自動デコード)
print(KULMS(auth).get("/portal").text)                      # Sakai LMS
print(MyKULINE(auth).get("/opac/opac_search/").text)        # 図書館 OPAC
print(PandA(auth).get("/portal").text)                      # 旧 LMS (ECS CAS)

auth.close()
```


## Cookies

特定サービス向けの認証済みセッション cookie だけ欲しい場合は `service.cookies()` を使います。必要に応じて対象サービスのセッションを確立したうえで、そのサービスに送られる cookie を `httpx.Cookies` として返します。返り値は共有 cookie jar そのものではなく、対象サービス向けに切り出したコピーです。

```python
from kuauth import KyotoUAuth, KULASIS

auth = KyotoUAuth(
    username="a0XXXXXX",
    password="your-password",
    totp_secret="JBSWY3DPEHPK3PXP",
)

cookies = KULASIS(auth).cookies()
print(dict(cookies.items()))

auth.close()
```

## 認証方法

OTP が必要かどうかは、アクセスする SP によって変わります。

| Service  | Base URL                                  | 認証経路 | OTP |
| -------- | ----------------------------------------- | -------- | --- |
| KULASIS  | `https://www.k.kyoto-u.ac.jp`             | auth.iimc (SimpleSAMLphp) | 必要 |
| KULMS    | `https://lms.gakusei.kyoto-u.ac.jp`       | auth.iimc (SimpleSAMLphp) | 必要 |
| MyKULINE | `https://kuline.kulib.kyoto-u.ac.jp`      | authidp1 (Java Shib IdP)  | 不要 |
| PandA    | `https://panda.ecs.kyoto-u.ac.jp`         | ECS CAS                   | 不要 |

OTP は実際に OTP フォームに到達した時点で初めて解決されます。つまり、MyKULINE や PandA しか使わないスクリプトでは `totp_secret` 等の指定は省略できます。KULASIS / KULMS を叩く場合のみ、下記のいずれかを渡してください。

| 引数 | 用途 |
| --- | --- |
| `onetime_password="424242"` | 手元の 6 桁コードを 1 回だけ使う |
| `otp_callback=lambda: input("OTP: ")` | 対話的スクリプト |
| `totp_secret="JBSWY3DPEHPK3PXP"` | cron / CI など無人実行 |

TOTP シークレットは [京大の多要素認証マニュアル](https://www.iimc.kyoto-u.ac.jp/ja/services/account/mfa/manuals) に従って認証アプリを登録する際の QR に埋め込まれた `otpauth://totp/...?secret=XXXX&...` の `secret` パラメータです。登録後は QR が再表示されないので、登録画面で控えておくか、一度アプリを解除して再登録してください。

KUMOI (Microsoft 365) はテナント admin consent が必要なため、スコープ外です。

個別エンドポイントのラッパメソッドは持たない設計です。HAR ファイルから URL とフォーム構造を特定すれば、`KULASIS(auth).post(...)` などを使って呼び出し側で任意のページを叩けます。

## テスト

```bash
uv run pytest tests/unit -q      # ネットワーク不要
uv run pytest tests/replay -q    # respx でモックした E2E
```

実 IdP と実サービスを叩く統合テストは `KUAUTH_LIVE=1` を指定しない限り、すべてスキップされます。実行するには以下の環境変数をセットしてください。

`KUAUTH_TOTP_SECRET` は KULASIS / KULMS のテストに必要です。省略すると `auth_with_totp` を使うテストだけがスキップされます (MyKULINE / PandA は走ります)。

```bash
# bash / Git Bash
KUAUTH_LIVE=1 \
  KUAUTH_USERNAME=a0XXXXXX \
  KUAUTH_PASSWORD=... \
  KUAUTH_TOTP_SECRET=JBSWY3DPEHPK3PXP \
  uv run pytest tests/integration -q
```

```powershell
# PowerShell
$env:KUAUTH_LIVE="1"
$env:KUAUTH_USERNAME="a0XXXXXX"
$env:KUAUTH_PASSWORD="..."
$env:KUAUTH_TOTP_SECRET="JBSWY3DPEHPK3PXP"
uv run pytest tests/integration -q
```


## License

MIT — see [LICENSE](LICENSE).
