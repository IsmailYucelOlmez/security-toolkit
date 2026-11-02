#!/usr/bin/env python3
"""Derin tarama akışını sınamak için bilerek açıklı küçük API. Yalnızca 127.0.0.1'de dinler.

  /orders  sahiplik kontrolü YOK; başka kullanıcının siparişi okunabilir (IDOR)
  /notes   sahiplik kontrolü var; başka kullanıcıya 403 döner

Kullanım: authz_api.py <port>
"""
import json
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USERS = {"alice": "alice-parola", "bob": "bob-parola"}
TOKENS = {f"{name}-token": name for name in USERS}


def crud_paths(name):
    item = {"type": "object", "required": ["id", "text"],
            "properties": {"id": {"type": "integer"}, "text": {"type": "string"}}}
    body = {"type": "object", "required": ["text"], "properties": {"text": {"type": "string"}}}
    forbidden = {"description": "Yetkisiz"}
    return {
        f"/{name}": {"post": {
            "operationId": f"create_{name}",
            "requestBody": {"required": True, "content": {"application/json": {"schema": body}}},
            "responses": {"201": {"description": "Oluşturuldu",
                                  "content": {"application/json": {"schema": item}}},
                          "401": forbidden, "422": {"description": "Geçersiz"}},
        }},
        f"/{name}/{{item_id}}": {"get": {
            "operationId": f"read_{name}",
            "parameters": [{"name": "item_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
            "responses": {"200": {"description": "Kayıt", "content": {"application/json": {"schema": item}}},
                          "401": forbidden, "403": forbidden, "404": {"description": "Yok"}},
        }},
    }


SCHEMA = {
    "openapi": "3.0.3",
    "info": {"title": "authz fixture", "version": "1"},
    "security": [{"bearer": []}],
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    "paths": {**crud_paths("orders"), **crud_paths("notes")},
}
STORE = {"orders": {}, "notes": {}}


class Api(BaseHTTPRequestHandler):
    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def user(self):
        header = self.headers.get("Authorization", "")
        return TOKENS.get(header.removeprefix("Bearer "))

    def do_GET(self):
        if self.path == "/openapi.json":
            return self.reply(200, SCHEMA)
        user = self.user()
        if not user:
            return self.reply(401, {"detail": "kimlik gerekli"})
        parts = self.path.split("?")[0].strip("/").split("/")
        if len(parts) != 2 or parts[0] not in STORE or not parts[1].isdigit():
            return self.reply(404, {"detail": "yok"})
        record = STORE[parts[0]].get(int(parts[1]))
        if record is None:
            return self.reply(404, {"detail": "yok"})
        if parts[0] == "notes" and record["owner"] != user:
            return self.reply(403, {"detail": "yetkisiz"})
        return self.reply(200, {"id": record["id"], "text": record["text"]})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path == "/token":
            fields = dict(urllib.parse.parse_qsl(raw.decode(errors="replace")))
            name = fields.get("username", "")
            if USERS.get(name) != fields.get("password"):
                return self.reply(401, {"detail": "hatalı giriş"})
            return self.reply(200, {"access_token": f"{name}-token", "token_type": "bearer"})
        user = self.user()
        if not user:
            return self.reply(401, {"detail": "kimlik gerekli"})
        name = self.path.strip("/")
        if name not in STORE:
            return self.reply(404, {"detail": "yok"})
        try:
            body = json.loads(raw)
        except ValueError:
            return self.reply(422, {"detail": "geçersiz"})
        if not isinstance(body, dict) or not isinstance(body.get("text"), str):
            return self.reply(422, {"detail": "geçersiz"})
        new_id = len(STORE[name]) + 1
        STORE[name][new_id] = {"id": new_id, "text": body["text"], "owner": user}
        return self.reply(201, {"id": new_id, "text": body["text"]})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Api).serve_forever()
