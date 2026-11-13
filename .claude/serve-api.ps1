# Starts the SentinelAI API for UI work: secrets from the git-ignored .env.ui-dev (never printed),
# data from the UI-dev copy (never data/platform/).
$root = Split-Path -Parent $PSScriptRoot
Get-Content (Join-Path $root '.env.ui-dev') | ForEach-Object {
  if ($_ -match '^\s*([A-Z_]+)\s*=\s*(.*)$') { Set-Item -Path "env:$($Matches[1])" -Value $Matches[2] }
}
$env:SENTINEL_DATA_DIR = Join-Path $root 'data\processed\ui-dev'
$env:HF_HUB_OFFLINE = '1'; $env:TRANSFORMERS_OFFLINE = '1'
$env:SENTINEL_LLM_BASE_URL = 'http://127.0.0.1:11434/v1'
$env:SENTINEL_LLM_MODEL = 'sentinel-qwen2.5-7b-32k'
Set-Location (Join-Path $root 'backend')
& (Join-Path $root '.venv\Scripts\python.exe') -m app.main serve
