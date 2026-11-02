# Yetki matrisi testleri

Her uç nokta için her kullanıcının alması gereken yanıtı tablo olarak yazarsınız; test tabloyu sınar.
Haftalık Schemathesis kontrolü yalnızca başka kullanıcının nesnesini **okumayı** dener. Bu testler
yazma, silme ve admin işlemlerini de her PR'da sınar.

## Projeye eklemek

Şablon FastAPI içindir. Copier'da `authz_matrix` sorusuna evet derseniz `tests/test_authz_matrix.py` eklenir ve sonraki
güncellemelerde ezilmez. Elle de kopyalayabilirsiniz; `sample_app.py` gerekmez.

1. "PROJEYE GÖRE" işaretli üç yeri değiştirin: uygulama, kullanıcılar ve test verisi, matris. Değiştirene kadar test
   `sample_app` içe aktarımında hata verir.
2. Yazma fiillerini, admin uçlarını ve varsa kiracı sınırını da yazın; örnek matris üçünü de gösterir.
3. Testleri projenin CI'ına ekleyin: `pip install pytest httpx && pytest`

İlk çalıştırmada kapsam testi eksik uçları listeler; en hızlı başlangıç bu listeyi matrise taşımaktır.
Beklenen değerleri koda bakarak değil, kimin neye erişmesi gerektiğine göre yazın. Aksi halde test
mevcut hatayı doğru sayar.

## Kurallar

- Testler test veritabanında çalışır; gerçek hesap veya staging gerekmez.
- Satırda yazılmayan kullanıcı için erişimin reddedilmesi beklenir; yeni kullanıcı rolü eklemek varsayılan olarak yetki vermez.
- Reddedilen isteklerde `422` kabul edilmez. Doğrulama hatası yetkiden önce dönüyorsa test yetkiyi
  sınamamış olur; `BODIES` içine geçerli gövde ekleyin.
- `security-review` skill'i canlıda bir açık kanıtlarsa buraya satır önerir. Böylece açık geri
  dönerse PR aşamasında yakalanır.
