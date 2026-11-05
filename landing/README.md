# Aegis download page

Public, static site people download the endpoint agent from. The console (backend + dashboard) stays local.

```
public/
  index.html          the landing page (no build step, no framework)
  setup.ps1           launcher: finds the console on the LAN, asks to join, runs the console's installer
  Aegis-Setup.cmd     setup.ps1 wrapped for double-click (UAC once)      ← generated
  Aegis-Setup.zip     the .cmd zipped for download                         ← generated
build.sh              regenerates the .cmd and .zip; run after editing setup.ps1
```

## Deploy
Any static host, publish directory `public/`:
- Vercel: `cd landing/public && npx vercel --prod`
- Netlify: `npx netlify deploy --dir landing/public --prod`
- GitHub Pages / Cloudflare Pages: point it at `landing/public`.

Then tell the dashboard where it lives, so Endpoints > Add endpoint links to it:
```bash
cd dashboard && VITE_AEGIS_DOWNLOAD_URL=https://your-site.example npm run build
```

## How "automatic" works
1. setup.ps1 broadcasts `AEGIS-DISCOVER` on UDP 47800; the backend answers with its URL.
   If nothing answers (some Wi-Fi drops broadcast), it scans the local /24 for port 8000 and checks `/api/discover`.
2. It POSTs `/api/enroll/request`; the request pops up on the dashboard (Follow mode jumps to it).
   Approve it, or turn on "Approve every machine automatically" for the demo.
3. On approval it receives the enrollment token and runs `install.ps1` from the console, same as the manual one-liner.

Override discovery: `$env:AEGIS_CONSOLE='192.168.1.20:8000'` before running setup.
The Mac's firewall must allow Python incoming connections (TCP 8000 and UDP 47800).
