import os
from pathlib import Path
from domain.contracts.config import settings

print("=" * 60)
print("📍 ENVIRONMENT VARIABLES LOADED BY APP")
print("=" * 60)
print(f"Current working directory: {Path.cwd()}")
print(f"Looking for .env file in: {Path.cwd() / '.env'}")
print(f".env file exists: {os.path.exists('.env')}")
print("=" * 60)
print(f"DATABASE_URL: {settings.DATABASE_URL}")
print(f"LLM_PROVIDER: {settings.LLM_PROVIDER}")
print(f"DEBUG: {settings.DEBUG}")
print("=" * 60)

# بررسی محتوای فایل .env اگر وجود دارد
if os.path.exists('.env'):
    with open('.env', 'r', encoding='utf-8') as f:
        content = f.read()
    print("📄 Content of .env file:")
    print(content)
else:
    print("❌ .env file NOT found in root directory!")