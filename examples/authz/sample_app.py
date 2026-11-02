"""Yetki matrisi örneğinin üzerinde çalıştığı küçük FastAPI uygulaması. Projenizde kullanılmaz."""
from fastapi import Depends, FastAPI, Header, HTTPException

TOKENS = {"owner-token": "owner", "other-token": "other", "admin-token": "admin"}
orders: dict[int, dict] = {}
app = FastAPI()


def current_user(authorization: str = Header(default="")) -> str:
    user = TOKENS.get(authorization.removeprefix("Bearer "))
    if not user:
        raise HTTPException(401, "kimlik gerekli")
    return user


def own_order(order_id: int, user: str = Depends(current_user)) -> dict:
    order = orders.get(order_id)
    if order is None or (order["owner"] != user and user != "admin"):
        raise HTTPException(404, "yok")
    return order


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/orders/{order_id}")
def read_order(order: dict = Depends(own_order)):
    return order


@app.put("/orders/{order_id}")
def update_order(payload: dict, order: dict = Depends(own_order)):
    order.update(text=payload.get("text", ""))
    return order


@app.delete("/orders/{order_id}", status_code=204)
def delete_order(order: dict = Depends(own_order)):
    orders.pop(order["id"])


@app.get("/admin/orders")
def list_all_orders(user: str = Depends(current_user)):
    if user != "admin":
        raise HTTPException(403, "yetkisiz")
    return list(orders.values())
