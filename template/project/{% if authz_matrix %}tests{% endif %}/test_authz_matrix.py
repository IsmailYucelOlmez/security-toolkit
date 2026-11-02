"""Yetki matrisi: her uç nokta için her kullanıcının alması gereken yanıtı tanımlar.

"PROJEYE GÖRE" işaretli üç yeri değiştirin. Testler CI'da test veritabanıyla çalışır; staging veya gerçek
hesap gerekmez. Matriste olmayan bir uç eklenirse test başarısız olur, böylece yeni uçların yetkisi
unutulamaz. Satırda yazılmayan kullanıcı için beklenen sonuç erişimin reddedilmesidir.

Kurulum: pip install pytest httpx
"""
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

# PROJEYE GÖRE 1: uygulamanız
from sample_app import app, orders

ALLOW = {200, 201, 204}
# 422 bilerek yok: doğrulama hatası yetki kontrolünden önce dönüyorsa test yetkiyi sınamamış olur
DENY = {401, 403, 404}
ANON = {401}


# PROJEYE GÖRE 2: kullanıcılar ve her testten önce oluşturulan veriler
HEADERS = {
    "anon": {},
    "owner": {"Authorization": "Bearer owner-token"},
    "other": {"Authorization": "Bearer other-token"},
    "admin": {"Authorization": "Bearer admin-token"},
    "outsider": {"Authorization": "Bearer outsider-token"},  # başka kiracının kullanıcısı
}


def seed():
    """Kaydı 'owner' kullanıcısına ait oluşturur, yol parametrelerini döndürür."""
    orders.clear()
    orders[1] = {"id": 1, "text": "ilk", "owner": "owner", "tenant": "a"}
    return {"order_id": 1, "tenant_id": "a"}


# PROJEYE GÖRE 3: matris. Her satırda yalnızca erişebilecek kullanıcıları yazın; diğerleri için DENY beklenir.
MATRIX = {
    ("GET", "/health"): {"anon": ALLOW, "owner": ALLOW, "other": ALLOW, "admin": ALLOW, "outsider": ALLOW},
    # Yazma: giriş yapan herkes kendi kaydını oluşturabilir
    ("POST", "/orders"): {"owner": ALLOW, "other": ALLOW, "admin": ALLOW, "outsider": ALLOW},
    # Nesne düzeyinde yetki (BOLA): okuma, yazma ve silme ayrı ayrı sınanır
    ("GET", "/orders/{order_id}"): {"owner": ALLOW, "admin": ALLOW},
    ("PUT", "/orders/{order_id}"): {"owner": ALLOW, "admin": ALLOW},
    ("DELETE", "/orders/{order_id}"): {"owner": ALLOW, "admin": ALLOW},
    # İşlev düzeyinde yetki (BFLA): yalnızca admin
    ("GET", "/admin/orders"): {"admin": ALLOW},
    # Kiracı sınırı: başka kiracının kullanıcısı erişemez
    ("GET", "/tenants/{tenant_id}/orders"): {"owner": ALLOW, "other": ALLOW, "admin": ALLOW},
}
# Yazma isteklerinin yetki kontrolüne ulaşması için geçerli gövdeler
BODIES = {("PUT", "/orders/{order_id}"): {"text": "yeni"}, ("POST", "/orders"): {"text": "yeni"}}

CASES = [(method, path, actor, rules.get(actor, DENY))
         for (method, path), rules in MATRIX.items()
         for actor in HEADERS]


def declared_routes():
    return {(method, route.path)
            for route in app.routes if isinstance(route, APIRoute)
            for method in route.methods - {"HEAD", "OPTIONS"}}


@pytest.mark.parametrize("method,path,actor,expected", CASES,
                         ids=[f"{m} {p} [{a}]" for m, p, a, _ in CASES])
def test_authorization(method, path, actor, expected):
    url = path.format(**seed())
    response = TestClient(app).request(method, url, headers=HEADERS[actor], json=BODIES.get((method, path)))
    assert response.status_code in expected, f"{actor} {method} {url}: {response.status_code}"


def test_every_route_is_in_the_matrix():
    assert declared_routes() - set(MATRIX) == set(), "Bu uçlar için matrise satır ekleyin"


def test_matrix_has_no_stale_routes():
    assert set(MATRIX) - declared_routes() == set(), "Bu uçlar artık yok; matristen çıkarın"


def test_matrix_uses_known_actors():
    unknown = {actor for rules in MATRIX.values() for actor in rules} - set(HEADERS)
    assert unknown == set(), "Bu kullanıcılar HEADERS içinde yok"


def test_anonymous_gets_401_not_just_any_denial():
    # Reddedilen anonim istek 401 olmalı; 404 kimlik doğrulamasının atlandığını gizleyebilir
    url_args = seed()
    for (method, path), rules in MATRIX.items():
        if "anon" not in rules:
            response = TestClient(app).request(method, path.format(**url_args), json=BODIES.get((method, path)))
            assert response.status_code in ANON, f"anon {method} {path}: {response.status_code}"
