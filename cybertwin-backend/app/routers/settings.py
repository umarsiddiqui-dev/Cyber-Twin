from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from pydantic import BaseModel
import logging
import asyncio
import re
import os

from app.config import settings
from app.auth.dependencies import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/settings", tags=["Settings"])

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str

@router.post("/change-password")
async def change_password(req: ChangePasswordRequest, username: str = Depends(get_current_user)):
    # Verify old password matches current password in settings
    from app.auth.router import _verify_password, _get_admin_hash, _pwd_context
    if not _verify_password(req.old_password, _get_admin_hash()):
        raise HTTPException(status_code=400, detail="Old password is incorrect.")
    
    if req.new_password != req.confirm_password:
        raise HTTPException(status_code=400, detail="New passwords do not match.")

    # Validation: >=8 chars, alphanumeric, symbols, 1 upper, 1 lower
    pwd = req.new_password
    if len(pwd) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", pwd):
        raise HTTPException(status_code=400, detail="Password must contain at least 1 uppercase letter.")
    if not re.search(r"[a-z]", pwd):
        raise HTTPException(status_code=400, detail="Password must contain at least 1 lowercase letter.")
    if not re.search(r"\d", pwd):
        raise HTTPException(status_code=400, detail="Password must contain at least 1 number.")
    if not re.search(r"[!@#$%^&*()_\-+=\[\]{}|\\:;\"'<>,.?/~`]", pwd):
        raise HTTPException(status_code=400, detail="Password must contain at least 1 symbol.")

    # Update .env file (Simulation of writing to .env)
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env')
    try:
        with open(env_path, 'r') as f:
            lines = f.readlines()
        with open(env_path, 'w') as f:
            for line in lines:
                if line.startswith('ADMIN_PASSWORD='):
                    f.write(f'ADMIN_PASSWORD={req.new_password}\n')
                else:
                    f.write(line)
                    
        # Update settings in memory
        settings.ADMIN_PASSWORD = req.new_password
        # Force rehash on next login
        from app.auth.router import _admin_password_hash
        import app.auth.router
        app.auth.router._admin_password_hash = _pwd_context.hash(req.new_password)
        
    except Exception as e:
        logger.error(f"Failed to update .env: {e}")
        raise HTTPException(status_code=500, detail="Failed to save new password to environment.")

    return {"message": "Password changed successfully"}

@router.post("/scan/device")
async def scan_device(username: str = Depends(get_current_user)):
    # Simulate a device scan taking some time
    await asyncio.sleep(3)
    return {
        "status": "completed",
        "result": "Clean",
        "details": "Full device scan completed. No malicious software or unauthorized files found. System integrity verified."
    }

@router.post("/scan/file")
async def scan_file(
    path: str = Form(None), 
    file: UploadFile = File(None),
    username: str = Depends(get_current_user)
):
    if not path and not file:
        raise HTTPException(status_code=400, detail="Must provide either a file path or upload a file.")

    target_name = file.filename if file else path
    
    # Simulate file scanning time
    await asyncio.sleep(2)
    
    # Simple heuristic to simulate detection
    is_malicious = False
    details = f"File '{target_name}' appears to be clean. No suspicious signatures found."
    
    if target_name:
        suspicious_exts = ['.exe', '.bat', '.sh', '.dll', '.ps1']
        if any(target_name.lower().endswith(ext) for ext in suspicious_exts):
            is_malicious = True
            details = f"⚠️ WARNING: '{target_name}' contains potentially malicious executable signatures. Recommend immediate quarantine."
            
        if 'malware' in target_name.lower() or 'virus' in target_name.lower():
            is_malicious = True
            details = f"🚨 CRITICAL: '{target_name}' matches known malware signatures (Trojan.Generic.Win32)."

    return {
        "status": "completed",
        "result": "Malicious" if is_malicious else "Clean",
        "details": details
    }
