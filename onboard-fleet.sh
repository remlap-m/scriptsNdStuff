#!/bin/bash
# onboard-fleet.sh
# Run once from Azure Cloud Shell, after the deploy workflow has completed.
# Onboards MDE + Sysmon across the whole Windows/Linux fleet, and runs the
# single-target scripts (CA, file share, honeytoken) - all via
# `az vm run-command`, which authenticates through Azure RBAC and needs no
# domain trust, no share, no WinRM. See conversation for the full reasoning.
#
# BEFORE RUNNING:
#   1. Download the Windows MDE onboarding package from Defender portal
#      (Settings -> Endpoints -> Onboarding -> Windows -> Local Script) and
#      upload it to Cloud Shell (upload icon in the toolbar).
#   2. Download the Linux MDE onboarding package the same way
#      (Onboarding -> Linux Server -> Local Script) and upload it too.
#   3. Update the two file paths below to match what you uploaded.
#
# Nothing tenant-specific in this file ever gets committed to GitHub -
# it's assembled and run entirely within your own Cloud Shell session.

set -euo pipefail

RESOURCE_GROUP="RG-INFRA-LAB-EPHEMERAL"
REPO_RAW="https://raw.githubusercontent.com/remlap-m/secops-lab/main/scripts"

# --- Fleet inventory -------------------------------------------------------
WINDOWS_VMS=(vm-eph-dc01 vm-eph-ca01 vm-eph-fs01 vm-eph-win11-1 vm-eph-win11-2 vm-eph-win11-3 vm-eph-win11-4 vm-eph-jump01)
LINUX_VMS=(vm-eph-lnx01 vm-eph-atk01)

# --- Your uploaded MDE packages - UPDATE THESE PATHS ------------------------
WINDOWS_MDE_FILE="$HOME/WindowsMDEOnboarding.cmd"
LINUX_MDE_FILE="$HOME/LinuxMDEOnboarding.py"

echo "=== 1. Confirm domain build succeeded ==="
az vm run-command invoke -g "$RESOURCE_GROUP" -n vm-eph-dc01 \
  --command-id RunPowerShellScript --scripts "Get-ADDomain | Select-Object DNSRoot,DomainMode"

echo "=== 2. Sysmon on every Windows VM (public script, fetched live from repo) ==="
for vm in "${WINDOWS_VMS[@]}"; do
  echo "--- Sysmon: $vm ---"
  az vm run-command invoke -g "$RESOURCE_GROUP" -n "$vm" \
    --command-id RunPowerShellScript \
    --scripts "iwr -useb $REPO_RAW/windows/Install-Sysmon.ps1 | iex"
done

echo "=== 3. MDE onboarding - Windows fleet (assembled locally, never committed) ==="
win_b64=$(base64 -w0 "$WINDOWS_MDE_FILE")
cat > "$HOME/_mde-windows.ps1" <<EOF
\$bytes = [Convert]::FromBase64String("$win_b64")
[IO.File]::WriteAllBytes("C:\\onboard.cmd", \$bytes)
& cmd.exe /c "echo Y| C:\\onboard.cmd"
EOF
for vm in "${WINDOWS_VMS[@]}"; do
  echo "--- MDE onboard: $vm ---"
  az vm run-command invoke -g "$RESOURCE_GROUP" -n "$vm" \
    --command-id RunPowerShellScript --scripts @"$HOME/_mde-windows.ps1"
done

echo "=== 4. MDE onboarding - Linux fleet ==="
lnx_b64=$(base64 -w0 "$LINUX_MDE_FILE")
cat > "$HOME/_mde-linux.sh" <<EOF
echo "$lnx_b64" | base64 -d > /tmp/onboard.py
sudo apt-get update -y
sudo apt-get install -y mdatp
sudo python3 /tmp/onboard.py
EOF
for vm in "${LINUX_VMS[@]}"; do
  echo "--- MDE onboard: $vm ---"
  az vm run-command invoke -g "$RESOURCE_GROUP" -n "$vm" \
    --command-id RunShellScript --scripts @"$HOME/_mde-linux.sh"
done

echo "=== 5. Single-target steps (public scripts, fetched live from repo) ==="
az vm run-command invoke -g "$RESOURCE_GROUP" -n vm-eph-ca01 \
  --command-id RunPowerShellScript --scripts "iwr -useb $REPO_RAW/windows/Install-CA.ps1 | iex"

az vm run-command invoke -g "$RESOURCE_GROUP" -n vm-eph-fs01 \
  --command-id RunPowerShellScript --scripts "iwr -useb $REPO_RAW/windows/Setup-FileShare.ps1 | iex"

az vm run-command invoke -g "$RESOURCE_GROUP" -n vm-eph-dc01 \
  --command-id RunPowerShellScript --scripts "iwr -useb $REPO_RAW/windows/New-HoneytokenAccount.ps1 | iex"

echo "=== 6. Cleanup local temp files (contain no secrets, but tidy anyway) ==="
rm -f "$HOME/_mde-windows.ps1" "$HOME/_mde-linux.sh"

echo "=== Done. Verify devices in Defender portal -> Assets -> Devices. ==="
