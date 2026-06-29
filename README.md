# OLSPanel PM2 & Node.js Application Manager Plugin

An official plugin for **OLSPanel** to deploy, run, and manage Node.js applications with **PM2** process isolation and automatic OpenLiteSpeed reverse proxy routing.

## Features
- **PM2 Integration**: Start, stop, restart, delete, and monitor Node.js processes from a beautiful web GUI.
- **Process Security Isolation**: Automatically spawns and runs Node.js applications under each site's specific Linux system user.
- **Interactive Metrics Banners**: CPU and memory usage meters per process updated in real-time.
- **Auto Reverse Proxy Mapping**: Links Node applications to domains and automatically injects OLS proxy context rules in one click.
- **Environment variables editor**: Interactive manager to edit `.env` configurations securely.
- **Live Logs Streamer**: Real-time console logs terminal view inside the control panel.

## Installation

*Note: The command line installation instructions must be run with root/administrative privileges (e.g. prefix with `sudo` or run directly as root depending on your system configuration).*

### Method 1: Direct Command Line (Recommended)
You can install the latest release directly:
```bash
install_cp_plugin https://github.com/ongudidan/olspanel-plugin-pm2/releases/latest/download/pm2.zip
```

Or target a specific version (e.g., `v1.0.0`):
```bash
install_cp_plugin https://github.com/ongudidan/olspanel-plugin-pm2/releases/download/v1.0.0/pm2_v1.0.0.zip
```

### Method 2: Manual Web UI
1. Go to the **Releases** page of this repository.
2. Download either the static `pm2.zip` or the version-specific `pm2_vX.Y.Z.zip` asset.
3. Log into your **OLSPanel Admin Control Panel**.
4. Go to **Plugins** -> **Install Plugin** and upload the downloaded zip.
5. Wait for the automatic reload to complete.

## Development & Packing
To pack the plugin manually, run this from the root of the repository:
```bash
zip -r pm2.zip pm2/ -x "*/.git*" -x "*.git*"
```

## Release Automation

### Option 1: Trigger via GitHub UI (Auto-increment)
1. Navigate to the **Actions** tab on GitHub.
2. Select the **Build and Release...** workflow.
3. Click the **Run workflow** button, select version level increment (`patch`, `minor`, `major`), and run.
4. The system will automatically compute the next version, tag it, and publish the release.

### Option 2: Manual Tag Push
If you prefer manual versioning:
```bash
git tag v1.0.0
git push origin v1.0.0
```
This triggers the Action to compile and publish that exact version.
