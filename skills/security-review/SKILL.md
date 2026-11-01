---
name: security-review
description: Projenin güvenliğini inceler: security-toolkit taramasını çalıştırır, bulguları kodla doğrular, araçların kaçırdığı yetkilendirme hatalarını arar ve düzeltme önerir.
---

# Güvenlik incelemesi

CI'daki deterministik tarama "ne var?" sorusunu yanıtlar; bu skill "bu gerçek mi, ne kadar önemli,
nasıl düzelir ve araçlar neyi kaçırdı?" sorularını yanıtlar. Kullanıcıya Türkçe rapor ver.

## 1. Toolkit'i bul

Sırayla dene, ilk bulunanı kullan:
1. `$SECURITY_TOOLKIT_DIR` ortam değişkeni
2. Projede `.security-toolkit/` veya kullanıcının ev dizininde `security-toolkit/`
3. Projedeki `.security-toolkit-answers.yml` içindeki `github_owner` ile
   `git clone --depth 1 https://github.com/<owner>/security-toolkit ~/.cache/security-toolkit`
4. Docker varsa: `docker run --rm -v "$PWD:/src" ghcr.io/<owner>/security-toolkit:latest --fail-on none`

Hiçbiri yoksa araçları (`bandit`, `pip-audit`, `semgrep`, `gitleaks`, `osv-scanner`) tek tek çalıştır
ve bunu raporda belirt.

## 2. Taramayı çalıştır

```bash
command -v gitleaks osv-scanner semgrep >/dev/null || bash "$TK/scripts/install-tools.sh"
bash "$TK/scripts/scan.sh" --path . --fail-on none
```

Proje `security-reports/findings.json` zaten yeni bir CI çıktısıysa (ör. kullanıcı indirip verdi)
yeniden çalıştırmak yerine onu kullan. `findings.json` içindeki `tools` listesinde `missing`/`error`
olan araçları raporda açıkça söyle — kör noktalar bulgular kadar önemlidir.

## 3. Bulguları doğrula (en önemli adım)

`findings.json`'daki her bulgu için ilgili kodu oku ve sınıflandır:

- **Gerçek** — istismar edilebilir bir yol var. Kullanıcı girdisinin bu noktaya nasıl ulaştığını tek
  cümleyle göster (ör. "`q` parametresi `/books` uç noktasından doğrudan `text(f"...")`'e gidiyor").
- **Yanlış pozitif** — neden olmadığını kanıtla (sabit değer, test kodu, ulaşılamayan yol).
- **Bağlama bağlı** — ne bilgisi gerektiğini söyle.

Bağımlılık açıklarında: paketin açıklı fonksiyonu projede kullanılıyor mu (`grep`)? Doğrudan mı dolaylı
bağımlılık mı? `fixed_version`'a yükseltmenin kırıcı değişiklik içerip içermediğini sürüm notlarından
kontrol et (büyük sürüm atlaması varsa uyar).

Dereceyi gerekirse düzelt: araç `medium` dese bile kimlik doğrulamasız bir uç noktadaki SQL
injection `critical`'dır; yalnızca yerel CLI betiğindeki `subprocess` `low`'dur.

## 4. Araçların kaçırdıklarını elle ara

Yığına göre (`findings.json` → `stacks`) şu kontrolleri yap. Bunlar otomatik araçların en çok
kaçırdığı sınıflardır:

**Backend / API (OWASP API Security Top 10, ASVS)**
- Nesne düzeyinde yetkilendirme (BOLA/IDOR): ID alan her uç nokta, kaydın isteği yapan kullanıcıya
  ait olduğunu kontrol ediyor mu? Router'ları tek tek gez; `current_user` bağımlılığı olmayan veya
  sorguda `user_id` filtresi olmayan uç noktaları listele.
- İşlev düzeyinde yetkilendirme: admin işlemleri rol kontrolü yapıyor mu?
- Kimlik doğrulama: parolalar bcrypt/argon2 ile mi saklanıyor, JWT süresi ve algoritması sabit mi,
  giriş uç noktasında hız sınırı var mı?
- Toplu atama: Pydantic modelleri `is_admin`, `owner_id` gibi alanları istemciden kabul ediyor mu?
- Dosya yükleme: tür/boyut sınırı, dosya adının yol olarak kullanılması.
- Hata yanıtları ve loglar: yığın izi, token veya kişisel veri sızıyor mu?

**Mobil / Flutter (OWASP MASVS)**
- Gizli anahtarlar uygulama içinde mi (derlenmiş APK'dan çıkarılabilir)?
- Token'lar `flutter_secure_storage`'da mı?
- Release derlemesinde `android:usesCleartextTraffic`, debug logları, `kDebugMode` dışı log.
- Sertifika doğrulaması kapatılmış mı?

**Masaüstü / C#**
- SQL komutlarında `SqlParameter` kullanımı, bağlantı cümlesindeki parolalar, `app.config`'deki sırlar.
- Ağ paylaşımına veya yerel diske yazılan hassas veriler.

## 5. Raporla

Kısa ve eyleme dönük ol:

1. **Özet**: kaç gerçek bulgu, en kritik 3 tanesi, kör noktalar.
2. **Bulgular**: derece sırasıyla; her biri için konum, neden gerçek olduğu, düzeltme.
3. **Yanlış pozitifler**: tek satırlık gerekçeyle.
4. **Elle inceleme notları**: 4. adımdan çıkanlar.

## 6. Düzelt

- Kullanıcı isterse düzeltmeleri uygula; her düzeltme küçük ve ayrı olsun. İlgili test varsa çalıştır.
- Bağımlılık yükseltmesinde kilit dosyasını da güncelle ve testleri çalıştır.
- `.security-ignore.yml`'e kayıt eklemeyi yalnızca kullanıcı onaylarsa yap; her kayıtta `reason` ve
  mümkünse `expires` olsun. Gerçek bir açığı bastırmayı önerme.
- Değişiklikleri commit'leme veya push'lama işini kullanıcıya bırak, açıkça istemedikçe yapma.

## 7. Otomasyon eksikse

Projede `.github/workflows/security.yml` veya `.pre-commit-config.yaml` yoksa, raporun sonunda tek
cümleyle kurulumu öner: `copier copy gh:<owner>/security-toolkit . --trust`.

## Güvenlik sınırı

Bu skill yalnızca kullanıcının kendi projesinde veya açıkça yetkili olduğu sistemlerde çalışır.
Canlı sistemlere saldırı trafiği gönderen araçları (ZAP aktif tarama, Strix, Schemathesis) yalnızca
kullanıcı hedefi ve yetkiyi açıkça doğruladıktan sonra, tercihen staging ortamında çalıştır.
