from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
import jwt

# ruleid: fastapi-debug-enabled
app = FastAPI(debug=True)
# ok: fastapi-debug-enabled
safe_app = FastAPI(debug=False)

# ruleid: fastapi-cors-wildcard-with-credentials
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
# ok: fastapi-cors-wildcard-with-credentials
app.add_middleware(CORSMiddleware, allow_origins=["https://ornek.test"], allow_credentials=True)


def decode(token, key):
    # ruleid: jwt-decode-without-verification
    jwt.decode(token, options={"verify_signature": False})
    # ok: jwt-decode-without-verification
    return jwt.decode(token, key, algorithms=["HS256"])


# ruleid: hardcoded-secret-key
JWT_SECRET = "abcdefgh12345678"
# ok: hardcoded-secret-key
API_KEY = "changeme"
# ok: hardcoded-secret-key
TITLE = "abcdefgh12345678"


def query(db, q):
    # ruleid: sqlalchemy-text-fstring
    db.execute(text(f"SELECT * FROM b WHERE t = '{q}'"))
    # ok: sqlalchemy-text-fstring
    return db.execute(text("SELECT * FROM b WHERE t = :q"), {"q": q})
