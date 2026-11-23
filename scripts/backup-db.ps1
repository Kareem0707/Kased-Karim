<#
.SYNOPSIS
    Kased Karim Luxury Lighting - Automated Database Backup Script (PowerShell)
.DESCRIPTION
    Runs scheduled database backups every 4 hours, applies retention pruning, and calculates SHA256 checksums.
#>

param(
    [string]$DbHost = $env:DB_HOST,
    [string]$DbPort = $env:DB_PORT,
    [string]$DbName = $env:DB_NAME,
    [string]$DbUser = $env:DB_USER,
    [string]$DbPassword = $env:DB_PASSWORD,
    [string]$BackupDir = "",
    [int]$RetentionDays = 14
)

if ([string]::IsNullOrWhiteSpace($DbHost)) { $DbHost = "localhost" }
if ([string]::IsNullOrWhiteSpace($DbPort)) { $DbPort = "5432" }
if ([string]::IsNullOrWhiteSpace($DbName)) { $DbName = "kased_karim_db" }
if ([string]::IsNullOrWhiteSpace($DbUser)) { $DbUser = "kased_admin" }
if ([string]::IsNullOrWhiteSpace($DbPassword)) {
    Write-Error "Fail-Closed: DB_PASSWORD environment variable or parameter is required."
    exit 1
}

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptRoot

if ([string]::IsNullOrWhiteSpace($BackupDir)) {
    $BackupDir = Join-Path $ProjectRoot "backups"
}

if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupFileName = "kased_karim_backup_$Timestamp.sql"
$BackupPath = Join-Path $BackupDir $BackupFileName
$LogFile = Join-Path $BackupDir "backup.log"

function Write-BackupLog([string]$msg) {
    $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $msg"
    Write-Host $logEntry
    Add-Content -Path $LogFile -Value $logEntry
}

Write-BackupLog "================================================================="
Write-BackupLog "▶ بدء النسخ الاحتياطي لقاعدة بيانات قاصد كريم: $DbName على $DbHost:$DbPort"

$env:PGPASSWORD = $DbPassword

try {
    if (Get-Command pg_dump -ErrorAction SilentlyContinue) {
        & pg_dump -h $DbHost -p $DbPort -U $DbUser $DbName -f $BackupPath
        if ($LASTEXITCODE -eq 0 -and (Test-Path $BackupPath)) {
            $FileHash = (Get-FileHash -Path $BackupPath -Algorithm SHA256).Hash
            $FileSize = (Get-Item $BackupPath).Length / 1MB
            Write-BackupLog "✅ تم إنشاء النسخة بنجاح: $BackupFileName ($([Math]::Round($FileSize, 2)) MB)"
            Write-BackupLog "🔒 SHA256: $FileHash"
        } else {
            Write-BackupLog "❌ فشل تنفيذ pg_dump."
        }
    } else {
        Write-BackupLog "⚠️ تنبيه: pg_dump غير متوفر في مسار النظام. يرجى التأكد من تشغيله داخل حاوية Docker."
    }
} catch {
    Write-BackupLog "❌ خطأ أثناء النسخ: $_"
}

# Retention Cleanup
Write-BackupLog "🧹 تنظيف النسخ الأقدم من $RetentionDays يوم..."
$Cutoff = (Get-Date).AddDays(-$RetentionDays)
Get-ChildItem -Path $BackupDir -Filter "kased_karim_backup_*.sql*" | Where-Object { $_.LastWriteTime -lt $Cutoff } | ForEach-Object {
    Remove-Item $_.FullName -Force
    Write-BackupLog "  - تم حذف النسخة القديمة: $($_.Name)"
}

Write-BackupLog "🏁 اكتملت دورة النسخ. الدورة القادمة بعد 4 ساعات."
Write-BackupLog "================================================================="
