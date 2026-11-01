# security-toolkit

Tüm projeler için tek yerden yönetilen güvenlik otomasyonu: Python/FastAPI, Flutter ve C#/.NET
projelerini algılar, uygun araçları çalıştırır, sonuçları tek rapora toplar.

| Katman | Ne zaman | Ne yapar |
|---|---|---|
| **pre-commit** | Her commit | Sır sızıntısı, `.env`/anahtar dosyaları, Python SAST (hızlı) |
| **security-scan** workflow | Her PR / push / haftalık | Sırlar, bağımlılık açıkları, SAST, altyapı yapılandırması |
| **deep-scan** workflow | Haftalık / sürüm öncesi | Staging'e karşı Schemathesis, ZAP, Strix, MobSF |
| **Docker imajı** | CI olmayan ortamlar | Aynı taramayı tek komutla (fabrika ağı, Windows makineler) |
| **security-review** skill | İstendiğinde | Bulguları doğrular, araçların kaçırdıklarını arar, düzeltir |
| **DefectDojo** | Sürekli | Tüm projelerin bulgularını tek panelde toplar |

## Hangi araç neyi tarar

| Araç | Python | Flutter | C# / .NET | Docker / IaC |
|---|:-:|:-:|:-:|:-:|
| Gitleaks — sızdırılmış sırlar | ✅ | ✅ | ✅ | ✅ |
| OSV-Scanner — bağımlılık açıkları (kilit dosyaları) | ✅ | ✅ `pubspec.lock` | ✅ `packages.lock.json` | |
| pip-audit — `requirements*.txt` | ✅ | | | |
| Bandit — Python SAST | ✅ | | | |
| Semgrep — `p/default` + `rules/semgrep` özel kuralları | ✅ | ✅ | ✅ | |
| `dotnet list package --vulnerable` | | | ✅ | |
| Trivy — Dockerfile, Terraform, Kubernetes | | | | ✅ |

Özel Semgrep kuralları (`rules/semgrep/`) genel kural setlerinin kaçırdığı kalıpları yakalar:
FastAPI'de `*` CORS + kimlik bilgisi, debug modu, imzasız JWT, `text(f"...")` SQL; Flutter'da
gömülü API anahtarı, `SharedPreferences`'ta token, `badCertificateCallback`, şifresiz HTTP;
C#'ta birleştirmeyle kurulan `SqlCommand` ve bağlantı cümlesinde parola.

## Kurulum (bir kez)

1. Bu klasörü GitHub'da **`security-toolkit`** adlı bir repo olarak yayınlayın. İçinde sır yok;
   **public** olması en kolayı. Private olacaksa projelerde `TOOLKIT_TOKEN` secret'ı gerekir.
2. `.github/workflows/selftest.yml` ilk push'ta testleri, `docker-publish.yml` imajı GHCR'ye yayınlar.
3. Kararlı bir sürüm etiketi koyun: `git tag v1 && git push --tags` (projelerde `@v1` kullanın).

## Bir projeye eklemek

**Önerilen — Copier şablonu** (workflow, pre-commit, Dependabot ve bastırma dosyası birlikte gelir):

```bash
pipx install copier
cd ~/projeler/rubricator
copier copy gh:OWNER/security-toolkit . --trust
pre-commit install
```

Şablon güncellendiğinde tüm projelere uygulamak için her projede `copier update --trust`.

**Elle:** `examples/security.yml` dosyasını projenin `.github/workflows/` klasörüne kopyalayın,
`OWNER` kısmını değiştirin; `pre-commit/.pre-commit-config.yaml` dosyasını proje köküne kopyalayın.

## Yerel kullanım

```bash
bash scripts/install-tools.sh            # ~/.security-tools altına kurar (C# için --with-dotnet)
bash scripts/scan.sh --path ~/projeler/rubricator --fail-on high
```

Çıktılar `security-reports/` altında:
- `summary.md` — okunabilir özet (PR yorumunda da bu görünür)
- `findings.json` — normalize bulgular (skill ve DefectDojo bunu kullanır)
- `findings.sarif` — GitHub Security sekmesi için
- araçların ham çıktıları

Aynı açık birden çok araçtan gelirse tek kayda indirilir; bir paketin tüm açıkları tek satırda,
gereken en düşük güvenli sürümle gösterilir.

## Docker

```bash
docker run --rm -v "$PWD:/src" ghcr.io/OWNER/security-toolkit:latest --fail-on high
docker run --rm -v "$PWD:/src" ghcr.io/OWNER/security-toolkit:dotnet          # C# projeleri
```

Windows'ta: `docker\scan.ps1 -Path C:\Projeler\DurusMerkezi`

## Yanlış pozitifleri bastırmak

Projenin kökünde `.security-ignore.yml`:

```yaml
- id: B105                 # kural kimliği veya CVE/GHSA/PYSEC
  path: backend/tests/*    # isteğe bağlı
  reason: Test verisi
  expires: 2026-12-31      # bu tarihten sonra bulgu yeniden çıkar
```

Satır içi: `# nosec B105`, `# nosemgrep`, `# gitleaks:allow`.

## Derin tarama (staging)

Copier'da `deep_scan` seçilirse `security-deep.yml` eklenir; her cumartesi staging API'sine karşı
Schemathesis ve ZAP çalışır, Flutter varsa APK derlenip MobSF ile incelenir. Strix elle
tetiklemede seçilebilir (LLM maliyeti nedeniyle). Repo secrets:

| Secret | Gerekli olduğu yer |
|---|---|
| `API_AUTH_HEADER` | Kimlik doğrulamalı uç noktaları test etmek için, ör. `Bearer ...` (test kullanıcısı) |
| `STRIX_LLM`, `LLM_API_KEY` | Strix |
| `DEFECTDOJO_URL`, `DEFECTDOJO_TOKEN` | DefectDojo yüklemesi |

> ⚠️ Derin tarama hedefe saldırı trafiği gönderir. Yalnızca kendi staging ortamınızı hedefleyin;
> workflow `authorized: true` olmadan çalışmaz ve test ortamına benzemeyen adresler için uyarır.

## DefectDojo

Kendi sunucunuzda çalıştırmak için resmi docker-compose kurulumu:
<https://github.com/DefectDojo/django-DefectDojo> → `docker compose up -d`.
API token'ı kullanıcı menüsünden alın. `defectdojo/upload.sh` her araç için `reimport-scan`
kullanır: tekrar eden bulgular birleşir, düzelenler otomatik kapanır.

## Claude skill'i

`skills/security-review/SKILL.md` — taramayı çalıştırır, her bulguyu kodu okuyarak doğrular,
araçların kaçırdığı IDOR / yetkilendirme / toplu atama hatalarını elle arar ve düzeltme önerir.
"Bu projenin güvenliğini incele" demeniz yeterli.

## Bilinen sınırlar

- pip-audit önem derecesi vermez; OSV-Scanner aynı açığı bulursa onun derecesi kullanılır,
  bulamazsa `medium` sayılır.
- `packages.config` kullanan eski .NET Framework projeleri `dotnet list package` ile taranamaz;
  bu projeler için OSV-Scanner ve Semgrep sonuçları geçerlidir.
- Semgrep kural kayıt defterine ulaşamazsa yalnızca yerel kurallarla çalışır ve bunu raporda belirtir.

## Geliştirme

```bash
python -m unittest discover tests -v
shellcheck scripts/*.sh docker/*.sh defectdojo/*.sh
actionlint
```
