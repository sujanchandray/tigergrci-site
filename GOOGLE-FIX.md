# How to actually fix Google (not more github.io sitemap retries)

## Hard fact

Google Search Console **Couldn't fetch** on  
`https://sujanchandray.github.io/tigergrci-site/sitemap.xml`  
is a **known Google + GitHub Pages limitation**.  
The file is valid. Browsers open it. Googlebot can download it.  
**Editing `sitemap.xml` again will not clear the red status.**

Your homepage is already **URL is on Google** in Search Console.  
The remaining gap is sitemap Success + stronger discovery — that needs a host Google will process.

## Real fix (Cloudflare host)

Primary SEO URL to use:

`https://tigergrci.sujanray.workers.dev/`

### Step A — Authenticate Cloudflare (you must do this once)

In PowerShell:

```powershell
cd C:\TigerGRCi\website
npx wrangler login
```

Complete the browser login. Then tell the agent (or run):

```powershell
cd C:\TigerGRCi
node website/scripts/deploy-cloudflare-pages.js
```

(Or set `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID` and redeploy.)

### Step B — New Search Console property

1. Add URL-prefix property: `https://tigergrci.sujanray.workers.dev/`
2. Verify ownership
3. Submit sitemap: `sitemap.xml`
4. Request indexing for `/`, `/work-with-me.html`, `/privacy.html`
5. Put that URL on LinkedIn + GitHub Website

### Step C — Stop fighting the old property

Leave the `github.io` sitemap row alone. Do not delete/resubmit it every few minutes.

## After Cloudflare deploy succeeds

We will switch canonicals / sitemap `loc` URLs to `workers.dev` and republish.  
Until then, github.io keeps its own URLs so the current GSC property stays valid.
