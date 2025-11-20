import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from pydantic import BaseModel, Field

# Database (MongoDB helper provided by the environment)
from database import db

# Optional bcrypt via passlib
try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    _HASHING = True
except Exception:
    pwd_context = None
    _HASHING = False

# Auth / JWT settings
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# BSON ObjectId helper (safe import)
try:
    from bson import ObjectId
except Exception:
    ObjectId = None

app = FastAPI(title="Učilnica AI Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Models ----------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AuthRequest(BaseModel):
    username: str = Field(min_length=3, max_length=40)
    password: str = Field(min_length=6, max_length=128)
    full_name: Optional[str] = None
    school_id: Optional[str] = None


class User(BaseModel):
    id: str
    username: str
    full_name: Optional[str] = None
    school_id: Optional[str] = None


class ClassCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    subject: Optional[str] = None


class JoinClass(BaseModel):
    join_code: str = Field(min_length=6, max_length=12)


class MaterialCreate(BaseModel):
    class_id: str
    title: str
    type: str  # note, test, image, pdf, docx, pptx, other
    url: Optional[str] = None  # placeholder for storage URL
    description: Optional[str] = None


# ---------- Helpers ----------

def hash_password(password: str) -> str:
    if _HASHING and pwd_context:
        try:
            return pwd_context.hash(password)
        except Exception:
            pass
    # Fallback (NOT for production): prefix to mark plaintext
    return f"plain::{password}"


def verify_password(password: str, password_hash: str) -> bool:
    if password_hash.startswith("plain::"):
        return password_hash == f"plain::{password}"
    if _HASHING and pwd_context:
        try:
            return pwd_context.verify(password, password_hash)
        except Exception:
            return False
    return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(authorization: Optional[str] = Header(None)) -> User:
    if not authorization:
        raise HTTPException(status_code=401, detail="Manjka glava Authorization")
    # Expecting standard 'Bearer <token>' or just token
    parts = authorization.split()
    token = parts[-1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        if not username:
            raise HTTPException(status_code=401, detail="Neveljaven žeton")
        doc = db["profile"].find_one({"username": username}) if db else None
        if not doc:
            raise HTTPException(status_code=401, detail="Uporabnik ne obstaja")
        return User(
            id=str(doc.get("_id")),
            username=doc.get("username"),
            full_name=doc.get("full_name"),
            school_id=doc.get("school_id"),
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Neveljaven ali potekel žeton")


# ---------- Schools seed ----------
DEMO_SCHOOLS = [
    {"id": "si-os-0001", "name": "OŠ Vič", "type": "OŠ", "city": "Ljubljana"},
    {"id": "si-ss-0002", "name": "Gimnazija Bežigrad", "type": "SŠ", "city": "Ljubljana"},
    {"id": "si-uni-0003", "name": "Univerza v Ljubljani — FRI", "type": "Fakulteta", "city": "Ljubljana"},
]

SLO_SCHOOL_NAMES = [
    "Alma Mater Europaea - Evropski center Maribor (samostojni visokošolski zavod)",
    "Biotehniška fakulteta (Univerza v Ljubljani)",
    "DOBA Fakulteta za uporabne družbene in poslovne študije Maribor (samostojni visokošolski zavod)",
    "Ekonomska fakulteta (Univerza v Ljubljani)",
    "Ekonomsko-poslovna fakulteta (Univerza v Mariboru)",
    "ERUDIO Izobraževalni center (samostojni visokošolski zavod)",
    "Evropska pravna fakulteta (Nova univerza)",
    "Fakulteta za aplikativno naravoslovje (Univerza v Novi Gorici)",
    "Fakulteta za arhitekturo (Univerza v Ljubljani)",
    "Fakulteta za družbene vede (Univerza v Ljubljani)",
    "Fakulteta za elektrotehniko (Univerza v Ljubljani)",
    "Fakulteta za elektrotehniko, računalništvo in informatiko (Univerza v Mariboru)",
    "Fakulteta za energetiko (Univerza v Mariboru)",
    "Fakulteta za farmacijo (Univerza v Ljubljani)",
    "Fakulteta za gradbeništvo in geodezijo (Univerza v Ljubljani)",
    "Fakulteta za gradbeništvo (Univerza v Mariboru)",
    "Fakulteta za humanistične študije (Univerza na Primorskem)",
    "Fakulteta za humanistiko (Univerza v Novi Gorici)",
    "Fakulteta za informacijske študije (Univerza v Novem mestu) (načrtovana)",
    "Fakulteta za kemijo in kemijsko tehnologijo (Univerza v Ljubljani)",
    "Fakulteta za kemijo in kemijsko tehnologijo (Univerza v Mariboru)",
    "Fakulteta za kmetijstvo (Univerza v Mariboru)",
    "Fakulteta za logistiko v Celju (Univerza v Mariboru)",
    "Fakulteta za management (Univerza na Primorskem)",
    "Fakulteta za matematiko in fiziko (Univerza v Ljubljani)",
    "Fakulteta za matematiko, naravoslovje in informacijske tehnologije Koper (FAMNIT) (Univerza na Primorskem)",
    "Fakulteta za organizacijske študije v Novem mestu (samostojni visokošolski zavod)",
    "Fakulteta za organizacijske vede (Univerza v Mariboru)",
    "Fakulteta za podiplomske državne in evropske študije (samostojni visokošolski zavod)",
    "Fakulteta za podiplomski študij (Univerza v Novi Gorici)",
    "Fakulteta za pomorstvo in promet Portorož (Univerza v Ljubljani)",
    "Fakulteta za računalništvo in informatiko (Univerza v Ljubljani)",
    "Fakulteta za slovenske študije Stanislava Škrabca (Univerza v Novi Gorici)",
    "Fakulteta za socialno delo (Univerza v Ljubljani)",
    "Fakulteta za strojništvo (Univerza v Ljubljani)",
    "Fakulteta za strojništvo (Univerza v Mariboru)",
    "Fakulteta za šport (Univerza v Ljubljani)",
    "Fakulteta za uporabne družbene študije (samostojni visokošolski zavod)",
    "Fakulteta za upravo (Univerza v Ljubljani)",
    "Fakulteta za varnostne vede (Univerza v Mariboru)",
    "Fakulteta za zdravstvene vede (Univerza v Mariboru)",
    "Fakulteta za znanosti o okolju (Univerza v Novi Gorici)",
    "Filozofska fakulteta (Univerza v Ljubljani)",
    "Filozofska fakulteta (Univerza v Mariboru)",
    "Fakulteta za naravoslovje in matematiko (Univerza v Mariboru)",
    "Fakulteta za zdravstvene vede (Visokošolsko središče Novo mesto)",
    "Institutum Studiorum Humanitatis - Fakulteta za podiplomski humanistični študij, Ljubljana (samostojni visokošolski zavod)",
    "Medicinska fakulteta (Univerza v Ljubljani)",
    "Medicinska fakulteta (Univerza v Mariboru)",
    "Mednarodna fakulteta za družbene in poslovne študije (samostojni visokošolski zavod)",
    "Mednarodna podiplomska šola Jožefa Stefana (samostojni visokošolski zavod)",
    "MLC Fakulteta za management in pravo Ljubljana (samostojni visokošolski zavod)",
    "Naravoslovnotehniška fakulteta (Univerza v Ljubljani)",
    "Pedagoška fakulteta (Univerza na Primorskem)",
    "Pedagoška fakulteta (Univerza v Ljubljani)",
    "Pedagoška fakulteta (Univerza v Mariboru)",
    "Poslovno-tehniška fakulteta (Univerza v Novi Gorici)",
    "Pravna fakulteta (Univerza v Ljubljani)",
    "Pravna fakulteta (Univerza v Mariboru)",
    "Teološka fakulteta (Univerza v Ljubljani)",
    "Veterinarska fakulteta (Univerza v Ljubljani)",
]


def _slugify(value: str) -> str:
    import re
    value = value.strip().lower()
    # replace special slovene chars
    value = (value
             .replace('č', 'c').replace('ć', 'c')
             .replace('š', 's')
             .replace('ž', 'z')
             .replace('đ', 'd'))
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-+", "-", value).strip('-')
    return value[:48]


def ensure_demo_schools():
    if db is None:
        return
    try:
        # Ensure base demo
        if db["school"].count_documents({}) == 0:
            db["school"].insert_many(DEMO_SCHOOLS)
        # Upsert extended list by name
        for name in SLO_SCHOOL_NAMES:
            if not name or len(name) == 1:
                continue
            existing = db["school"].find_one({"name": name})
            if not existing:
                sid = f"si-{_slugify(name)}"
                db["school"].insert_one({"id": sid, "name": name})
    except Exception:
        pass


# ---------- Routes ----------
@app.on_event("startup")
async def on_startup():
    ensure_demo_schools()


@app.get("/")
def root():
    return {"message": "Učilnica AI Backend teče"}


@app.get("/api/hello")
def hello():
    return {"message": "Pozdrav iz backend API-ja!"}


@app.get("/schools")
def list_schools():
    docs = list(db["school"].find({}, {"_id": 0})) if db else []
    return {"items": docs}


@app.post("/auth/signup", response_model=Token)
def signup(auth: AuthRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Baza ni na voljo")
    exists = db["profile"].find_one({"username": auth.username})
    if exists:
        raise HTTPException(status_code=400, detail="Uporabnik že obstaja")
    doc = {
        "username": auth.username,
        "full_name": auth.full_name or auth.username,
        "email": f"{auth.username}@ucilnica.local",
        "school_id": auth.school_id,
        "password_hash": hash_password(auth.password),
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    db["profile"].insert_one(doc)
    token = create_access_token({"sub": auth.username, "username": auth.username})
    return Token(access_token=token)


@app.post("/auth/login", response_model=Token)
def login(auth: AuthRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Baza ni na voljo")
    doc = db["profile"].find_one({"username": auth.username})
    if not doc or not verify_password(auth.password, doc.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Napačno uporabniško ime ali geslo")
    token = create_access_token({"sub": auth.username, "username": auth.username})
    return Token(access_token=token)


@app.get("/me")
def me(user: User = Depends(get_current_user)):
    return user.dict()


@app.post("/classes")
def create_class(payload: ClassCreate, user: User = Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Baza ni na voljo")
    join_code = secrets.token_hex(3)  # 6 hex chars
    cls = {
        "name": payload.name,
        "subject": payload.subject,
        "owner": user.username,
        "join_code": join_code,
        "created_at": datetime.now(timezone.utc),
    }
    result = db["class"].insert_one(cls)
    # Add owner to class_members
    db["class_member"].insert_one({
        "class_id": str(result.inserted_id),
        "username": user.username,
        "role": "owner",
        "joined_at": datetime.now(timezone.utc),
    })
    return {"id": str(result.inserted_id), "join_code": join_code}


@app.post("/classes/join")
def join_class(payload: JoinClass, user: User = Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Baza ni na voljo")
    cls = db["class"].find_one({"join_code": payload.join_code})
    if not cls:
        raise HTTPException(status_code=404, detail="Razred s to kodo ne obstaja")
    class_id = str(cls.get("_id"))
    already = db["class_member"].find_one({"class_id": class_id, "username": user.username})
    if already:
        return {"status": "OK", "message": "Že si član tega razreda"}
    db["class_member"].insert_one({
        "class_id": class_id,
        "username": user.username,
        "role": "member",
        "joined_at": datetime.now(timezone.utc),
    })
    return {"status": "OK"}


@app.get("/classes")
def list_my_classes(user: User = Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Baza ni na voljo")
    memberships = list(db["class_member"].find({"username": user.username}))
    ids = [m.get("class_id") for m in memberships]
    classes = []
    if ids and ObjectId is not None:
        try:
            classes = [
                {**{k: v for k, v in c.items() if k != "_id"}, "id": str(c.get("_id"))}
                for c in db["class"].find({"_id": {"$in": [ObjectId(i) for i in ids if i]}})
            ]
        except Exception:
            classes = []
    return {"items": classes}


@app.get("/materials")
def list_materials(class_id: str, user: User = Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Baza ni na voljo")
    membership = db["class_member"].find_one({"class_id": class_id, "username": user.username})
    if not membership:
        raise HTTPException(status_code=403, detail="Nisi član tega razreda")
    items = [
        {**{k: v for k, v in d.items() if k != "_id"}, "id": str(d.get("_id"))}
        for d in db["material"].find({"class_id": class_id}).sort("created_at", -1)
    ]
    return {"items": items}


@app.post("/materials")
def create_material(payload: MaterialCreate, user: User = Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Baza ni na voljo")
    membership = db["class_member"].find_one({"class_id": payload.class_id, "username": user.username})
    if not membership:
        raise HTTPException(status_code=403, detail="Nisi član tega razreda")
    mat = {
        "class_id": payload.class_id,
        "title": payload.title,
        "type": payload.type,
        "url": payload.url,
        "description": payload.description,
        "owner": user.username,
        "created_at": datetime.now(timezone.utc),
    }
    res = db["material"].insert_one(mat)
    return {"id": str(res.inserted_id)}


# Simple health
@app.get("/test")
def test():
    status = "❌ Not Connected"
    try:
        if db is not None:
            col_names = db.list_collection_names()
            status = "✅ Connected" if isinstance(col_names, list) else "⚠️ Unknown"
        else:
            status = "❌ Not Configured"
    except Exception:
        status = "⚠️ Error"
    return {"backend": "✅ Running", "database": status}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
