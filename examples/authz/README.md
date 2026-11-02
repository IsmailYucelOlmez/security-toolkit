# Yetki matrisi testleri

Her uç nokta için her kullanıcının alması gereken yanıtı tablo olarak yazarsınız; test tabloyu sınar.
Haftalık Schemathesis kontrolü yalnızca başka kullanıcının nesnesini **okumayı** dener. Bu testler
yazma, silme ve admin işlemlerini de her PR'da sınar.

## Projeye eklemek

Şablon FastAPI içindir. Copier ile gelmez, çünkü projenin uygulamasına ve test verisine bağlıdır.

1. `test_authz_matrix.py` dosyasını projenin testlerine kopyalayın. `sample_app.py` gerekmez.
2. "PROJEYE GÖRE" işaretli üç yeri değiştirin: uygulama, kullanıcılar ve test verisi, matris.
3. Testleri projenin CI'ına ekleyin: `pip install pytest httpx && pytest`

İlk çalıştırmada kapsam testi eksik uçları listeler; en hızlı başlangıç bu listeyi matrise taşımaktır.
Beklenen değerleri koda bakarak değil, kimin neye erişmesi gerektiğine göre yazın. Aksi halde test
mevcut hatayı doğru sayar.

## Kurallar

- Testler test veritabanında çalışır; gerçek hesap veya staging gerekmez.
- Reddedilen isteklerde `422` kabul edilmez. Doğrulama hatası yetkiden önce dönüyorsa test yetkiyi
  sınamamış olur; `BODIES` içine geçerli gövde ekleyin.
- `security-review` skill'i canlıda bir açık kanıtlarsa buraya satır önerir. Böylece açık geri
  dönerse PR aşamasında yakalanır.
