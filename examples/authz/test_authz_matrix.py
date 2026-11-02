"""Yetki matrisi: her uç nokta için her kullanıcının alması gereken yanıtı tanımlar.

Projenize kopyalayıp "PROJEYE GÖRE" işaretli üç yeri değiştirin. Testler CI'da test veritabanıyla
çalışır; staging veya gerçek hesap gerekmez. Matriste olmayan bir uç eklenirse test başarısız olur,
böylece yeni uçların yetkisi unutulamaz.

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
}


def seed():
    """Kaydı 'owner' kullanıcısına ait oluşturur, yol parametrelerini döndürür."""
    orders.clear()
    orders[1] = {"id": 1, "text": "ilk", "owner": "owner"}
    return {"order_id": 1}


# PROJEYE GÖRE 3: matris. Tüm uçlar, tüm kullanıcılar için yazılmalıdır.
MATRIX = {
    ("GET", "/health"): {"anon": ALLOW, "owner": ALLOW, "other": ALLOW, "admin": ALLOW},
    ("GET", "/orders/{order_id}"): {"anon": ANON, "owner": ALLOW, "other": DENY, "admin": ALLOW},
    ("PUT", "/orders/{order_id}"): {"anon": ANON, "owner": ALLOW, "other": DENY, "admin": ALLOW},
    ("DELETE", "/orders/{order_id}"): {"anon": ANON, "owner": ALLOW, "other": DENY, "admin": ALLOW},
    ("GET", "/admin/orders"): {"anon": ANON, "owner": DENY, "other": DENY, "admin": ALLOW},
}
# Yazma isteklerinin yetki kontrolüne ulaşması için geçerli gövdeler
BODIES = {("PUT", "/orders/{order_id}"): {"text": "yeni"}}

CASES = [(method, path, actor, expected)
         for (method, path), rules in MATRIX.items()
         for actor, expected in rules.items()]


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


def test_every_row_covers_every_actor():
    incomplete = [key for key, rules in MATRIX.items() if set(rules) != set(HEADERS)]
    assert incomplete == [], "Bu satırlarda eksik kullanıcı var"
