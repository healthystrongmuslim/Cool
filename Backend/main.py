import os
import shutil
import re
import asyncio
import hashlib
import secrets
import base64
from datetime import datetime, timedelta
from typing import Dict, Optional, List

# Third-party imports
from fastapi import FastAPI, Request, HTTPException, Depends, UploadFile, File, Form, Body
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from bson import ObjectId
import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytz
from dotenv import load_dotenv

# Local imports
from db import users_collection, files_collection, logs_collection, folders_collection

# Load Env Vars
load_dotenv()

app = FastAPI()

# --- Configuration & Security Constants ---
# Fetch AES key from env and convert hex string back to bytes
_aes_key_hex = os.getenv("AES_KEY")
if not _aes_key_hex:
    raise RuntimeError("AES_KEY must be set in .env")
AES_KEY = bytes.fromhex(_aes_key_hex)

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
UPLOAD_DIR = "uploads"
TOKEN_EXPIRATION_MINUTES = 30
MAX_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=10)

# Security: Limit allowed file types to prevent executing malicious scripts
ALLOWED_EXTENSIONS = {
    ".txt", ".pdf", ".png", ".jpg", ".jpeg", ".gif", 
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip"
}

PASSWORD_PATTERN = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@#$!%*?&])[A-Za-z\d@#$!%*?&]{8,}$'

# Initialize Directories
os.makedirs(UPLOAD_DIR, exist_ok=True)

# In-Memory Storage (Note: For production, use Redis)
sessions: Dict[str, dict] = {} 
login_attempts: Dict[str, dict] = {}

# --- Pydantic Models ---
class LoginRequest(BaseModel):
    username: str
    password: str

class UploadMeta(BaseModel):
    username: str
    visible_to: Optional[List[str]] = None

class RegisterRequest(BaseModel):
    username: str
    password: str

class UpdateUserRequest(BaseModel):
    current_username: str
    new_username: Optional[str] = None
    new_password: Optional[str] = None

class FolderVisibilityRequest(BaseModel):
    visible_to: List[str]

# --- Helper Functions ---

def now_pk():
    """Returns current time in Asia/Karachi timezone."""
    return datetime.now(pytz.timezone("Asia/Karachi"))

def sanitize_filename(filename: str) -> str:
    """
    Security Fix: Prevent Path Traversal (e.g., ../../etc/passwd).
    Only allow alphanumeric, underscore, dash, and dot.
    """
    filename = os.path.basename(filename)
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)

def validate_file_extension(filename: str):
    """Security Fix: Prevent uploading executable files."""
    _, ext = os.path.splitext(filename)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400, 
            detail=f"File type not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )

def hash_username(username: str) -> str:
    return hashlib.sha256(username.lower().strip().encode()).hexdigest()

def validate_password(password: str) -> bool:
    return bool(re.match(PASSWORD_PATTERN, password))

async def log_action(username: str, action: str):
    log_entry = {
        "username": username,
        "action": action,
        "timestamp": now_pk().isoformat()
    }
    await logs_collection.insert_one(log_entry)

def encrypt_field(value: str) -> str:
    aesgcm = AESGCM(AES_KEY)
    nonce = hashlib.sha256(value.lower().strip().encode()).digest()[:12]
    encrypted = aesgcm.encrypt(nonce, value.encode(), None)
    return base64.b64encode(nonce + encrypted).decode()

def decrypt_field(encrypted_value: str) -> str:
    aesgcm = AESGCM(AES_KEY)
    data = base64.b64decode(encrypted_value)
    nonce, ciphertext = data[:12], data[12:]
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted.decode()

def hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def generate_token(username: str) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = now_pk() + timedelta(minutes=TOKEN_EXPIRATION_MINUTES)
    sessions[token] = {
        "username": username,
        "expires_at": expires_at
    }
    return token

def cleanup_expired_tokens():
    current_time = now_pk()
    expired_tokens = [t for t, d in sessions.items() if d["expires_at"] < current_time]
    for t in expired_tokens:
        del sessions[t]

# --- Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080",      # Vite default port
        "http://127.0.0.1:8080",
        "http://localhost:3000",      # React default port
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Dependencies ---
def auth_user(request: Request):
    token = request.headers.get("Authorization")
    if not token or token not in sessions:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    cleanup_expired_tokens()
    
    if token not in sessions:
        raise HTTPException(status_code=401, detail="Token expired")
    
    session_data = sessions[token]
    if session_data["expires_at"] < now_pk():
        del sessions[token]
        raise HTTPException(status_code=401, detail="Token expired")
    
    return session_data["username"]

# --- Routes ---

@app.post("/register")
async def register_user(req: RegisterRequest, username=Depends(auth_user)):
    if username != "admin":
        raise HTTPException(status_code=403, detail="Only admin can register users")
    
    if req.username.lower() == "admin":
        raise HTTPException(status_code=400, detail="Username 'admin' is reserved")

    if not validate_password(req.password):
        raise HTTPException(status_code=400, detail="Password complexity requirement not met.")

    hashed_username = hash_username(req.username)
    if await users_collection.find_one({"username_hash": hashed_username}):
        raise HTTPException(status_code=400, detail="User already exists")

    user_data = {
        "username": encrypt_field(req.username),
        "username_hash": hashed_username,
        "password": hash_password(req.password),
        "role": encrypt_field("user"),
    }

    await users_collection.insert_one(user_data)
    await log_action(req.username, "User registered")
    return {"message": "User registered"}

@app.post("/login")
async def login(req: LoginRequest):
    username = req.username
    now = now_pk()

    # Brute force protection
    if username in login_attempts:
        attempt = login_attempts[username]
        if attempt.get("locked_until") and now < attempt["locked_until"]:
            wait = int((attempt["locked_until"] - now).total_seconds() / 60)
            raise HTTPException(status_code=403, detail=f"Account locked. Try again in {wait} mins")

    # Authentication logic
    hashed_username = hash_username(username)
    user = await users_collection.find_one({"username_hash": hashed_username})
    
    if user:
        try:
            if verify_password(req.password, user["password"]):
                # Success - clear attempts
                if username in login_attempts:
                    del login_attempts[username]
                
                token = generate_token(req.username)
                
                # Decrypt role safely
                try:
                    user_role = decrypt_field(user["role"])
                except:
                    user_role = "user"

                await log_action(req.username, "User logged in")
                return {
                    "message": "Success",
                    "token": token,
                    "role": user_role,
                    "expires_in_minutes": TOKEN_EXPIRATION_MINUTES
                }
        except Exception:
            pass 

    # Handle Failure
    attempt = login_attempts.get(username, {"count": 0})
    attempt["count"] += 1
    attempt["last_failed"] = now
    
    if attempt["count"] >= MAX_ATTEMPTS:
        attempt["locked_until"] = now + LOCKOUT_DURATION
        login_attempts[username] = attempt
        raise HTTPException(status_code=403, detail="Too many failed attempts. Account locked.")
    
    login_attempts[username] = attempt
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/logout")
async def logout(request: Request):
    token = request.headers.get("Authorization")
    if token and token in sessions:
        username = sessions[token]["username"]
        del sessions[token]
        await log_action(username, "User logged out")
    return {"message": "Logged out successfully"}

@app.post("/admin-login")
async def admin_login(req: LoginRequest):
    if req.username != "admin" or req.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = generate_token("admin")
    await log_action("admin", "Admin logged in")
    return {
        "message": "Admin logged in successfully",
        "token": token,
        "expires_in_minutes": TOKEN_EXPIRATION_MINUTES
    }

@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    folder: str = Form(...),
    username=Depends(auth_user)
):
    # 1. Sanitize Folder
    clean_folder = re.sub(r"[^\w\-]", "_", folder)
    
    # 2. Check Folder Permission
    # Allow upload if folder exists AND user has access (either creator or shared)
    folder_doc = await folders_collection.find_one({"folder_name": clean_folder})
    
    has_access = False
    if folder_doc:
        visible_list = folder_doc.get("visible_to", [])
        if username in visible_list or username == "admin":
            has_access = True
    elif username == "admin":
        has_access = True # Admin can create folders via upload
        
    if not has_access:
         raise HTTPException(status_code=403, detail="Folder not found or access denied")

    # 3. Sanitize Filename
    clean_filename = sanitize_filename(file.filename)
    
    # 4. Validate Extension
    validate_file_extension(clean_filename)

    user_dir = os.path.join(UPLOAD_DIR, username)
    upload_path = os.path.join(user_dir, clean_folder)
    os.makedirs(upload_path, exist_ok=True)

    file_path = os.path.join(upload_path, clean_filename)
    
    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)

    # 5. Inherit Visibility
    visible_to = []
    if folder_doc:
        visible_to = folder_doc.get("visible_to", [])
    
    # Ensure creator/admin always have access
    if username not in visible_to: visible_to.append(username)
    if "admin" not in visible_to: visible_to.append("admin")

    file_doc = {
        "filename": clean_filename,
        "path": file_path,
        "uploaded_by": username,
        "folder": clean_folder,
        "uploaded_at": now_pk().isoformat(),
        "visible_to": visible_to
    }
    new_file = await files_collection.insert_one(file_doc)
    await log_action(username, f"Uploaded file: {clean_filename}")
    
    # FIX: Return Full Object to prevent Frontend Crash
    return {
        "message": "File uploaded successfully",
        "file": {
            "id": str(new_file.inserted_id),
            "filename": clean_filename,
            "folder": clean_folder,
            "uploaded_by": username,
            "uploaded_at": file_doc["uploaded_at"],
            "visible_to": visible_to
        }
    }

@app.get("/download/{file_id}")
async def download_file(file_id: str, username=Depends(auth_user)):
    if not ObjectId.is_valid(file_id):
        raise HTTPException(status_code=400, detail="Invalid ID format")

    file_doc = await files_collection.find_one({"_id": ObjectId(file_id)})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")
    
    if username not in file_doc.get("visible_to", ["admin"]) and username != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    if not os.path.exists(file_doc["path"]):
         raise HTTPException(status_code=404, detail="File missing from disk")

    await log_action(username, f"Downloaded file: {file_doc['filename']}")
    return FileResponse(file_doc["path"], filename=file_doc['filename'])

@app.get("/files")
async def list_files(username=Depends(auth_user)):
    files_cursor = files_collection.find()
    all_files = []
    async for doc in files_cursor:
        # Safety: Ensure visible_to is a list
        visible_to = doc.get("visible_to", [])
        if not isinstance(visible_to, list): visible_to = []

        if username in visible_to or username == "admin":
            all_files.append({
                "id": str(doc["_id"]),
                "filename": doc["filename"],
                "folder": doc.get("folder", ""),
                "uploaded_by": doc["uploaded_by"],
                "uploaded_at": doc.get("uploaded_at"),
                "visible_to": visible_to # Send strict list back
            })
    
    # Fetch folders with robust query
    query = {
        "$or": [
            {"created_by": username},
            {"visible_to": username},
            {"visible_to": "admin"}
        ]
    }
    
    if username != "admin":
        # Strictly limit query for non-admins to be safe
        pass 
    else:
        # Admin sees everything, but we can stick to the OR query which includes admin
        pass

    folder_cursor = folders_collection.find(query)
    user_folders = []
    seen_folders = set()

    async for d in folder_cursor:
        f_id = str(d["_id"])
        if f_id not in seen_folders:
            seen_folders.add(f_id)
            user_folders.append({
                "id": f_id, 
                "folder_name": d["folder_name"], 
                "created_by": d["created_by"],
                "created_at": d.get("created_at"),
                "visible_to": d.get("visible_to", [])
            })

    return {"files": all_files, "folders": user_folders}

@app.get("/folders")
async def list_folders(username=Depends(auth_user)):
    # Redirect to list_files logic to keep it DRY or specific endpoint
    query = {
        "$or": [
            {"created_by": username},
            {"visible_to": username},
            {"visible_to": "admin"}
        ]
    }
    cursor = folders_collection.find(query)
    folders = []
    async for doc in cursor:
        folders.append({
            "id": str(doc["_id"]),
            "folder_name": doc["folder_name"],
            "created_by": doc["created_by"],
            "created_at": doc.get("created_at"),
            "visible_to": doc.get("visible_to", [])
        })
    return {"folders": folders}

@app.post("/create-folder")
async def create_folder(body: dict = Body(...), username=Depends(auth_user)):
    folder_name = body.get("folder_name")
    if not folder_name:
        raise HTTPException(status_code=400, detail="folder_name required")
    
    clean_name = re.sub(r"[^\w\-]", "_", folder_name)
    user_dir = os.path.join(UPLOAD_DIR, username)
    folder_path = os.path.join(user_dir, clean_name)

    existing = await folders_collection.find_one({"folder_name": clean_name})
    if existing:
        raise HTTPException(status_code=400, detail="Folder exists (globally)")

    os.makedirs(folder_path, exist_ok=True)

    visible_to = body.get("visible_to", [])
    if username not in visible_to: visible_to.append(username)
    if "admin" not in visible_to: visible_to.append("admin")

    folder_doc = {
        "folder_name": clean_name,
        "created_by": username,
        "created_at": now_pk().isoformat(),
        "path": folder_path,
        "visible_to": visible_to
    }
    await folders_collection.insert_one(folder_doc)
    await log_action(username, f"Created folder: {clean_name}")
    return {"message": "Folder created"}

@app.delete("/file/{file_id}")
async def delete_file(file_id: str, username=Depends(auth_user)):
    if username != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")
    
    if not ObjectId.is_valid(file_id):
        raise HTTPException(status_code=400, detail="Invalid ID")

    file_doc = await files_collection.find_one({"_id": ObjectId(file_id)})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")
    
    if os.path.exists(file_doc["path"]):
        try:
            os.remove(file_doc["path"])
        # except:
        #     pass
        except OSError:
            pass
    
    await files_collection.delete_one({"_id": ObjectId(file_id)})
    await log_action(username, f"Deleted file: {file_doc['filename']}")
    return {"message": "File deleted"}

@app.delete("/folder/{folder_name}")
async def delete_folder(folder_name: str, username=Depends(auth_user)):
    if username != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")
    
    clean_name = re.sub(r"[^\w\-]", "_", folder_name)
    folder_doc = await folders_collection.find_one({"folder_name": clean_name})
    if not folder_doc:
        raise HTTPException(status_code=404, detail="Folder not found")

    if await files_collection.count_documents({"folder": clean_name}) > 0:
        raise HTTPException(status_code=400, detail="Folder not empty")

    if os.path.exists(folder_doc["path"]):
        try:
            os.rmdir(folder_doc["path"])
        except OSError:
             pass 

    await folders_collection.delete_one({"_id": folder_doc["_id"]})
    await log_action(username, f"Deleted folder: {clean_name}")
    return {"message": "Folder deleted"}

@app.get("/users")
async def list_users(username=Depends(auth_user)):
    if username != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    users = []
    async for user in users_collection.find():
        users.append({
            "username": decrypt_field(user["username"]),
            "role": decrypt_field(user["role"])
        })
    return {"users": users}

@app.get("/disk-space")
async def get_disk_space(username=Depends(auth_user)):
    total, used, free = shutil.disk_usage(UPLOAD_DIR)
    return {"free_space_gb": round(free / (1024 ** 3), 2)}

@app.get("/token-status")
async def token_status(username=Depends(auth_user), request: Request = None):
    token = request.headers.get("Authorization")
    if token and token in sessions:
        session_data = sessions[token]
        time_remaining = session_data["expires_at"] - now_pk()
        minutes_remaining = max(0, int(time_remaining.total_seconds() / 60))
        
        # SECURITY FIX: Determine role server-side
        role = "user"
        if username == "admin":
            role = "admin"
        else:
            hashed = hash_username(username)
            user_doc = await users_collection.find_one({"username_hash": hashed})
            if user_doc:
                try:
                    role = decrypt_field(user_doc["role"])
                except:
                    pass

        return {
            "username": username,
            "role": role,  # <-- Sending the true role to the frontend
            "minutes_remaining": minutes_remaining,
            "expires_at": session_data["expires_at"].isoformat()
        }
    return {"message": "No active session"}

@app.get("/logs")
async def get_logs(username=Depends(auth_user)):
    if username == "admin":
        logs_cursor = logs_collection.find()
    else:
        logs_cursor = logs_collection.find({"username": username})

    return [
        {
            "username": log["username"],
            "action": log["action"],
            "timestamp": log["timestamp"]
        }
        async for log in logs_cursor
    ]

@app.put("/folder/{folder_name}/visibility")
async def update_folder_visibility(folder_name: str, req: FolderVisibilityRequest, username=Depends(auth_user)):
    if username != "admin":
        raise HTTPException(status_code=403, detail="Only admin can update folder visibility")
    
    sanitized = re.sub(r"[^\w\-]", "_", folder_name)
    folder_doc = await folders_collection.find_one({"folder_name": sanitized})
    if not folder_doc:
        raise HTTPException(status_code=404, detail="Folder not found")

    new_visible_to = req.visible_to
    if folder_doc["created_by"] not in new_visible_to:
        new_visible_to.append(folder_doc["created_by"])
    if "admin" not in new_visible_to:
        new_visible_to.append("admin")

    await folders_collection.update_one(
        {"_id": folder_doc["_id"]},
        {"$set": {"visible_to": new_visible_to}}
    )
    await files_collection.update_many(
        {"folder": sanitized},
        {"$set": {"visible_to": new_visible_to}}
    )
    
    await log_action(username, f"Updated visibility for folder: {folder_name}")
    return {"message": f"Visibility updated for folder '{folder_name}'"}

@app.delete("/user/{target_username}")
async def delete_user(target_username: str, username=Depends(auth_user)):
    if username != "admin":
        raise HTTPException(status_code=403, detail="Only admin can delete users")
    
    if target_username.lower() == "admin":
        raise HTTPException(status_code=403, detail="Cannot delete the admin user")
    
    hashed_username = hash_username(target_username)
    user = await users_collection.find_one({"username_hash": hashed_username})
    if user:
        await users_collection.delete_one({"_id": user["_id"]})
        await log_action(username, f"Deleted user {target_username}")
        return {"message": f"User '{target_username}' deleted successfully"}
    
    raise HTTPException(status_code=404, detail="User not found")

@app.put("/user/update")
async def update_user(req: UpdateUserRequest, username=Depends(auth_user)):
    if username != "admin":
        raise HTTPException(status_code=403, detail="Only admin can update users")
    
    hashed_current = hash_username(req.current_username)
    target_user = await users_collection.find_one({"username_hash": hashed_current})
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    update_fields = {}
    if req.new_username:
        hashed_new = hash_username(req.new_username)
        if await users_collection.find_one({"username_hash": hashed_new}):
            raise HTTPException(status_code=400, detail="Username exists")
        update_fields["username"] = encrypt_field(req.new_username)
        update_fields["username_hash"] = hashed_new
        
    if req.new_password:
        if not validate_password(req.new_password):
            raise HTTPException(status_code=400, detail="Weak password")
        update_fields["password"] = hash_password(req.new_password)

    if update_fields:
        await users_collection.update_one({"_id": target_user["_id"]}, {"$set": update_fields})
        await log_action(username, f"Updated user {req.current_username}")
        return {"message": "User updated"}
    
    return {"message": "No changes made"}

@app.on_event("startup")
async def startup_event():
    async def periodic_cleanup():
        while True:
            await asyncio.sleep(300)
            cleanup_expired_tokens()
    asyncio.create_task(periodic_cleanup())