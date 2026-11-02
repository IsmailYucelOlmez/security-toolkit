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
3. Kararlı bir sürüm etiketi koyun: `git tag v2.0.1 && git push --tags` (projelerde `@v2.0.1` kullanın).
   Şablon varsayılan olarak `v2.0.1` kullanır; bu etiket yoksa projelerde tarama başlamaz.

## Bir projeye eklemek

**Önerilen — Copier şablonu** (workflow, pre-commit, Dependabot ve bastırma dosyası birlikte gelir):

```bash
pipx install copier
cd ~/projeler/rubricator
copier copy gh:OWNER/security-toolkit . --trust
pre-commit install
```

Şablon güncellendiğinde tüm projelere uygulamak için her projede:

```bash
copier recopy -a .security-toolkit-answers.yml --defaults --overwrite --trust
```

`.security-ignore.yml` korunur; diğer şablon dosyalarındaki elle yapılmış değişiklikler ezilir.
`copier update` kullanmayın: taşınan sürüm etiketinde eski ve yeni sürümü ayırt edemez, hata vermeden
hiçbir şey değiştirmez.

**Eski sürümlerden geçiş:** v2'de DefectDojo girdileri kaldırıldı, deep-scan'e ikinci kullanıcı eklendi.
Cevap dosyası eski etiketi korur, bu yüzden geçişte etiketi açıkça verin. Yeni şablonu `v1`
workflow'uyla birlikte kullanmak çalışmaz. v2.0.1'de Dependabot'a 7 günlük bekleme süresi eklendi;
`v2` şablonuyla üretilen projelerin PR'ı bu bulgu yüzünden başarısız olur, güncelleyin.

```bash
copier recopy -a .security-toolkit-answers.yml --defaults --overwrite --trust -d toolkit_ref=v2.0.1
```

**Elle:** `examples/security.yml` dosyasını projenin `.github/workflows/` klasörüne kopyalayın,
`OWNER` kısmını değiştirin; `pre-commit/.pre-commit-config.yaml` dosyasını proje köküne kopyalayın.

## Güvenli kullanım

Her proje taramada toolkit'teki kodu çalıştırır; bu yüzden şablon şunları uygular:

- **Sürüm sabitleme:** `toolkit_ref` dal adı kabul etmez. `v2.0.1` gibi bir etiket veya daha sıkı
  sabitleme için tam commit SHA'sı girin. Elle kurulumda `uses: ...@` ve `toolkit-ref` aynı olmalı;
  `toolkit-ref` verilmezse betikler `main`'den gelir.
- **Yalnızca gereken secret'lar:** `secrets: inherit` kullanılmaz, her secret açıkça aktarılır.
- **Araç bütünlüğü:** Gitleaks, OSV-Scanner ve Trivy `scripts/tool-checksums.txt` içindeki sürümle kurulur, SHA-256
  özeti tutmayan dosya kurulmaz. Yükseltmek için sürüm notlarını okuyup
  `bash scripts/update-tool-checksums.sh <gitleaks> <osv-scanner> <trivy>` çalıştırın. Aksiyonlar commit SHA'sıyla,
  taban imaj, ZAP ve MobSF digest ile sabittir. Dependabot aksiyonları ve Dockerfile'ı günceller; ZAP digest'ini ve
  checksum dosyasını güncellemez. `dotnet-install.sh` ile Python araçlarının paketleri özetle doğrulanmaz, Python araçları
  yalnızca sürümle sabittir.

### Public projelerde raporlar

Workflow repo görünürlüğünü her çalışmada GitHub API'sinden okur. Repo public ise veya görünürlük
doğrulanamazsa tarama sonucu şöyle ele alınır:

| Çıktı | Public repoda |
|---|---|
| PR yorumu, iş özeti, tarama logu, rapor artifact'i | Bulgu yazılmaz |
| Security sekmesi (SARIF) | Push, zamanlanmış ve elle başlatılan taramalarda otomatik yüklenir; görünürlük doğrulanamazsa yüklenmez |
| PR'daki Code Scanning notları | Yüklenmez; okuma yetkisi olan herkes görebilirdi |
| Derin tarama | Çalışmaz, hata verir; çıktıları yalnızca log ve artifact'te tutulur |

PR hâlâ eşik aşılırsa başarısız olur; bu da bulgu olduğunu, ama ayrıntısını değil, herkese gösterir.
Ayrıntı için taramayı yerelde çalıştırın veya birleştirme sonrası Security sekmesine bakın.

## Yerel kullanım

```bash
bash scripts/install-tools.sh            # ~/.security-tools altına kurar (C# için --with-dotnet)
bash scripts/scan.sh --path ~/projeler/rubricator --fail-on high
```

Çıktılar `security-reports/` altında:
- `summary.md` — okunabilir özet (private repoda PR yorumunda da bu görünür)
- `findings.json` — normalize bulgular (skill bunu kullanır)
- `findings.sarif` — GitHub Security sekmesi için
- araçların ham çıktıları

Aynı açık birden çok araçtan gelirse tek kayda indirilir; bir paketin tüm açıkları tek satırda,
gereken en düşük güvenli sürümle gösterilir.

### Çıkış kodları

| Kod | Anlamı |
|---|---|
| `0` | Tarama tamam, eşik üstü bulgu yok |
| `1` | Eşik üstü bulgu var |
| `2` | Kullanım hatası |
| `3` | Tarama eksik: araç yok veya hata verdi, Semgrep yalnızca yerel kurallarla çalıştı, rapor okunamadı, manifestin kilit dosyası yok ya da hiçbir araç çalışmadı |

Eksik tarama eşik aşımından önce gelir ve temiz sonuç olarak gösterilmez. Eldeki bulgular yine rapora yazılır,
`findings.json` içinde `complete: false` olur. Çalışmayan aracın Security sekmesindeki uyarıları kapanmasın diye
eksik taramanın SARIF'i yüklenmez. Public repoda iş özetinde yalnızca araç adı ve durumu görünür.

Bir aracı bilerek çalıştırmıyorsanız `--skip` kullanın; atlanan araç eksiklik sayılmaz. `--skip osv` kilit dosyası
kontrolünü de kapatır. Ağsız ortamlarda `--allow-incomplete` eksikliği başarısızlık saymaz, raporda uyarı kalır.
`--fail-on none` yalnızca raporlama modudur ve eksik taramada da `0` döner.

## Docker

```bash
docker run --rm -v "$PWD:/src" ghcr.io/OWNER/security-toolkit:latest --fail-on high
docker run --rm -v "$PWD:/src" ghcr.io/OWNER/security-toolkit:dotnet          # C# projeleri
```

Windows'ta: `docker\scan.ps1 -Path C:\Projeler\DurusMerkezi`

## Windows'ta Docker'sız kullanım

`install-tools.sh` ve `scan.sh` Git Bash'te çalışır (Windows x64); Python kurulu olmalıdır:

```bash
bash scripts/install-tools.sh
bash scripts/scan.sh --path /c/projeler/rubricator --fail-on high
```

Git Bash, komut satırında `/` ile başlayan değerleri Windows yoluna çevirir. `copier` ile
`-d python_dir=/` gibi değerler vermeyin; varsayılan zaten `/`, soruları etkileşimli yanıtlamak da güvenlidir.
Vermeniz gerekirse komutun başına `MSYS_NO_PATHCONV=1` ekleyin.

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

Yalnızca private repolarda çalışır. Copier'da `deep_scan` seçilirse `security-deep.yml` eklenir; her cumartesi staging API'sine karşı
Schemathesis ve ZAP çalışır, Flutter varsa APK derlenip MobSF ile incelenir. Strix varsayılan olarak
kapalıdır, yalnızca elle tetiklemede seçilir. Repo secrets:

| Secret | Gerekli olduğu yer |
|---|---|
| `TEST_USER_EMAIL`, `TEST_USER_PASSWORD` | `api_login_url` verilirse: Schemathesis ve ZAP taramadan önce giriş yapıp taze token alır |
| `TEST_USER_B_EMAIL`, `TEST_USER_B_PASSWORD` | İsteğe bağlı ikinci kullanıcı: Schemathesis'te IDOR kontrolünü açar (`api_login_url` gerekir) |
| `API_AUTH_HEADER` | Giriş adresi yoksa sabit başlık, ör. API anahtarı |
| `STRIX_LLM`, `LLM_API_KEY` | Yalnızca Strix kullanılacaksa |

Test kullanıcısı için:

- Hesap **yalnızca staging'de** bulunsun, canlıda kullanılan bir parola olmasın. Sabit token süresi
  dolarak kendiliğinden geçersizleşir; parola ise siz değiştirene kadar geçerlidir.
- En düşük yetkiyle, MFA gerektirmeden çalışacak şekilde ayarlayın.
- Tarama giriş ucunu da hedef aldığı için hesabı kilitleme kuralından muaf tutun; aksi halde sonraki
  girişler başarısız olur. Çıkış ve parola değiştirme uçları da test kullanıcısının token'ını
  geçersiz kılabilir.
- Giriş başarısız olursa iş durur, kimliksiz taramaya sessizce düşmez. Token ZAP taraması sürerken
  dolarsa yenilenmez; süresini en az bir saat tutun.

### Yetki kontrolleri

Schemathesis işi, kimlik doğrulaması uygulanmayan bir uç (`ST401`) veya başka kullanıcının nesnesini
okuyabilen bir kullanıcı (`ST402`, IDOR) bulursa başarısız olur. Şema yüklenemezse veya hiçbir işlem
test edilemezse de başarısız olur. Diğer kontrollerin bulguları yalnızca raporlanır.

IDOR kontrolü yalnızca ikinci kullanıcı tanımlıysa çalışır; yoksa iş özeti bunu açıkça söyler. Bu
kontrol için API'nin kayıt oluşturup kimliğini döndürmesi (veya kullanıcıya özel liste sunması) ve
kaydı o kimlikle okuyan bir `GET` ucu olması gerekir. Kontrol okumayı sınar; yazma ve silme için
[yetki matrisi testlerini](examples/authz/README.md) kullanın. Tasarım gereği paylaşılan kaynaklar
yanlış pozitif verebilir.

Bulgular takip sistemine gitmez; özet ve artifact'te kalır. Artifact'e yazılmadan önce raporlarda
test kullanıcısı token'ı aranır, bulunursa rapor yüklenmez.

### Strix

Ödeme veya hassas veri içeren projelerde büyük sürüm öncesi tek seferlik kullanım içindir; düzenli
kontroller Schemathesis, [yetki matrisi](examples/authz/README.md) ve skill ile yapılır.

- Test kullanıcısı token'ları talimat olarak verilir ve **LLM sağlayıcısına gider**; kaynak kod da
  taranır. Bu yüzden yalnızca staging hesabı ve kısa ömürlü token kullanın.
- Giriş bilgisi yoksa canlı test girişsiz yüzeyle sınırlı kalır, iş özeti bunu belirtir.
- Token'lar artifact'ten önce maskelenir, telemetri kapalıdır, artifact 14 gün saklanır.
- Bulgu işi başarısız yapmaz, özette yazar. Tarama çalışamazsa iş başarısız olur.

> ⚠️ Derin tarama hedefe saldırı trafiği gönderir. Yalnızca kendi staging ortamınızı hedefleyin;
> workflow `authorized: true` olmadan çalışmaz ve test ortamına benzemeyen adresler için uyarır.

## Claude skill'i

`skills/security-review/SKILL.md` — taramayı çalıştırır, her bulguyu kodu okuyarak doğrular,
araçların kaçırdığı IDOR / yetkilendirme / toplu atama hatalarını elle arar ve düzeltme önerir.
"Bu projenin güvenliğini incele" demeniz yeterli.

"Bulguları staging'de kanıtla" derseniz iki test kullanıcısıyla istek atıp açığı doğrular. Her
oturumda hedef onayı ister, varsayılan olarak yalnızca okuma isteği gönderir. Kullanıcı bilgilerini
sohbete yazmayın; `~/.config/security-toolkit/staging-users.env` dosyasına koyun. Token'lar
`~/.cache/security-toolkit/` altında tutulur, iş bitince silinir. Windows'ta dosya izinleri
(`chmod 600`) bu dosyaları korumaz; yalnızca staging hesabı kullanın.

## Bilinen sınırlar

- pip-audit önem derecesi vermez; OSV-Scanner aynı açığı bulursa onun derecesi kullanılır,
  bulamazsa `medium` sayılır.
- `packages.config` kullanan eski .NET Framework projeleri `dotnet list package` ile taranamaz;
  bu projeler için OSV-Scanner ve Semgrep sonuçları geçerlidir. Tarama bu projelerde `3` döner; `--skip dotnet`
  (workflow'da `skip: dotnet`) ile çalıştırın.
- Semgrep kural kayıt defterine ulaşamazsa yalnızca yerel kurallarla çalışır, bunu raporda belirtir ve tarama `3`
  döner. Ağsız ortamlarda `--allow-incomplete` kullanın.
- Kilit dosyası kontrolü `pyproject.toml`, `setup.py`, `Pipfile`, `pubspec.yaml` ve `package.json` dosyalarına bakar;
  kilit dosyası aynı dizinde veya üst dizinlerde aranır. Bağımlılık tanımlamayan `pyproject.toml` ve `package.json` atlanır.

## Geliştirme

```bash
python -m unittest discover tests -v
python tests/e2e_authz.py    # pip install "schemathesis>=4.33,<5" gerekir
shellcheck scripts/*.sh docker/*.sh
actionlint
```
