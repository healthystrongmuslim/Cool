import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")

client = AsyncIOMotorClient(MONGO_URI)
db = client["file_storage_db"]  # Renamed to be more descriptive than 'admin'

users_collection = db["users"]
files_collection = db["files"]
logs_collection = db["logs"]
folders_collection = db["folders"]