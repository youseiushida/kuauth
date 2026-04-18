# kuauth

[![PyPI version](https://img.shields.io/pypi/v/kuauth.svg)](https://pypi.org/project/kuauth/)
[![Python](https://img.shields.io/pypi/pyversions/kuauth.svg)](https://pypi.org/project/kuauth/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Live integration](https://github.com/youseiushida/kuauth/actions/workflows/live-integration.yml/badge.svg?event=schedule)](https://github.com/youseiushida/kuauth/actions/workflows/live-integration.yml)
[![Context7 Indexed](https://img.shields.io/badge/Context7-Indexed-047857)](https://context7.com/youseiushida/kuauth)
[![Context7 llms.txt](https://img.shields.io/badge/Context7-llms.txt-047857)](https://context7.com/youseiushida/kuauth/llms.txt)

京都大学の SSO (KULASIS / KULMS / MyKULINE / PandA) を単一のセッションで
叩くための Python クライアント。初回の `get()` / `post()` 時に必要な IdP
ウォークが遅延実行され、それ以降は通常の HTTP クライアントとして使える。

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

## 認証方法

OTP が必要かどうかはアクセスする SP によって変わる:

| Service  | Base URL                                  | 認証経路 | OTP |
| -------- | ----------------------------------------- | -------- | --- |
| KULASIS  | `https://www.k.kyoto-u.ac.jp`             | auth.iimc (SimpleSAMLphp) | 必要 |
| KULMS    | `https://lms.gakusei.kyoto-u.ac.jp`       | auth.iimc (SimpleSAMLphp) | 必要 |
| MyKULINE | `https://kuline.kulib.kyoto-u.ac.jp`      | authidp1 (Java Shib IdP)  | 不要 |
| PandA    | `https://panda.ecs.kyoto-u.ac.jp`         | ECS CAS                   | 不要 |

OTP は実際に OTP フォームに到達した時点で初めて解決される。つまり
MyKULINE や PandA しか使わないスクリプトでは `totp_secret` 等の指定は
省略できる。KULASIS / KULMS を叩く場合のみ、下記のいずれかを渡す:

| 引数 | 用途 |
| --- | --- |
| `onetime_password="424242"` | 手元の 6 桁コードを 1 回だけ使う |
| `otp_callback=lambda: input("OTP: ")` | 対話的スクリプト |
| `totp_secret="JBSWY3DPEHPK3PXP"` | cron / CI など無人実行 |

TOTP シークレットは[京大の多要素認証マニュアル](https://www.iimc.kyoto-u.ac.jp/ja/services/account/mfa/manuals)
に従って認証アプリを登録する際の QR に埋め込まれた `otpauth://totp/...?secret=XXXX&...`
の `secret` パラメータ。登録後は QR が再表示されないので、登録画面で控えておくか、
一度アプリを解除して再登録する。

KUMOI (Microsoft 365) はテナント admin consent 要でスコープ外。

個別エンドポイントのラッパメソッドは持たない設計。HAR ファイルから URL と
フォーム構造を特定すれば、`KULASIS(auth).post(...)` などを使って呼び出し側で
任意のページを叩ける。

## テスト

```bash
uv run pytest tests/unit -q      # ネットワーク不要
uv run pytest tests/replay -q    # respx でモックした E2E
```

実 IdP と実サービスを叩く統合テストは `KUAUTH_LIVE=1` を指定しない限り
すべて skip される。実行するには以下の環境変数をセットする:

`KUAUTH_TOTP_SECRET` は KULASIS / KULMS のテストに必要で、省略すると
`auth_with_totp` を使うテストだけが skip される (MyKULINE / PandA は走る)。

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
