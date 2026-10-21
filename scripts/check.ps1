$ErrorActionPreference = 'Stop'

if (-not $env:VIRTUAL_ENV) {
  Write-Host 'Activate the backend venv first: backend\.venv\Scripts\Activate.ps1' -ForegroundColor Red
  exit 1
}

Push-Location (Join-Path $PSScriptRoot '..\backend')
try {
  $steps = @(
    @('ruff lint',   { python -m ruff check . }),
    @('ruff format', { python -m ruff format --check . }),
    @('mypy',        { python -m mypy }),
    @('pytest',      { python -m pytest })
  )

  foreach ($s in $steps) {
    Write-Host "== $($s[0])" -ForegroundColor Cyan
    & $s[1]
    if ($LASTEXITCODE -ne 0) {
      Write-Host "FAILED: $($s[0])" -ForegroundColor Red
      exit 1
    }
  }

  Write-Host 'ALL CHECKS PASSED' -ForegroundColor Green
}
finally {
  Pop-Location
}