# kuauth

京都大学の SSO (KULASIS / KULMS / MyKULINE / PandA) を単一のセッションで
叩くための Python クライアント。ログイン後は各サービスを通常の
`get()` / `post()` で呼び出せる。

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
).login()

print(KULASIS(auth).get("/student/u/t/top").text)           # 教務 (Shift_JIS 自動デコード)
print(KULMS(auth).get("/portal").text)                      # Sakai LMS
print(MyKULINE(auth).get("/opac/opac_search/").text)        # 図書館 OPAC
print(PandA(auth).get("/portal").text)                      # 旧 LMS (ECS CAS)

auth.close()
```

## 認証方法

OTP の渡し方は 3 通り。

| 引数 | 用途 |
| --- | --- |
| `onetime_password="424242"` | 手元の 6 桁コードを 1 回だけ使う |
| `otp_callback=lambda: input("OTP: ")` | 対話的スクリプト |
| `totp_secret="JBSWY3DPEHPK3PXP"` | cron / CI など無人実行 |

TOTP シークレットは[京大の多要素認証マニュアル](https://www.iimc.kyoto-u.ac.jp/ja/services/account/mfa/manuals)
に従って認証アプリを登録する際の QR に埋め込まれた `otpauth://totp/...?secret=XXXX&...`
の `secret` パラメータ。登録後は QR が再表示されないので、登録画面で控えておくか、
一度アプリを解除して再登録する。

## サービス一覧

| Service  | Base URL                                  | 認証 |
| -------- | ----------------------------------------- | ---- |
| KULASIS  | `https://www.k.kyoto-u.ac.jp`             | IIMC Shibboleth |
| KULMS    | `https://lms.gakusei.kyoto-u.ac.jp`       | IIMC Shibboleth |
| MyKULINE | `https://kuline.kulib.kyoto-u.ac.jp`      | IIMC Shibboleth |
| PandA    | `https://panda.ecs.kyoto-u.ac.jp`         | ECS CAS (OTP 不要) |

PandA は IIMC の Shibboleth ではなく ECS の CAS サーバで認証するため、
`KyotoUAuth` の `totp_secret` 等は使用されない (`username` / `password` のみ)。

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
