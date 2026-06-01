# CyberTwin ML Pipeline – Quick Start Script
# Run this ONCE to build the knowledge base and train the model.
# After this, the FastAPI backend will load the artifacts automatically.

$ErrorActionPreference = "Stop"
$backend = "C:\Users\Abiha Afzal\Documents\FINALYP\cybertwin-backend"
Set-Location $backend

Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  CyberTwin Phase 6 – ML Pipeline" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Step 1: Build knowledge base (fast ~2s)
Write-Host "[1/3] Building MITRE ATT&CK + NVD knowledge base..." -ForegroundColor Yellow
.\venv\Scripts\python ml_pipeline/knowledge_builder.py
Write-Host "  ✅ Knowledge base built." -ForegroundColor Green

# Step 2: Preprocess dataset (medium ~3 min)
Write-Host ""
Write-Host "[2/3] Preprocessing CSE-CIC-IDS2018 dataset (6.3M rows)..." -ForegroundColor Yellow
Write-Host "      (This takes ~3 minutes)" -ForegroundColor Gray
.\venv\Scripts\python ml_pipeline/data_preprocessing.py
Write-Host "  ✅ Preprocessing complete." -ForegroundColor Green

# Step 3: Train model (long ~15 min)
Write-Host ""
Write-Host "[3/3] Training LightGBM + Random Forest ensemble..." -ForegroundColor Yellow
Write-Host "      (This takes 10-20 minutes — go grab a coffee! ☕)" -ForegroundColor Gray
.\venv\Scripts\python ml_pipeline/model_trainer.py
Write-Host "  ✅ Model trained and saved to app/models/trained/" -ForegroundColor Green

Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  All done! Start the backend:" -ForegroundColor Green
Write-Host "  uvicorn app.main:app --reload" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
