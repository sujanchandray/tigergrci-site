# TigerGRCi founder site (free)

Static public site for **Sujan Chandra Ray** / **TigerGRCi**: problem, visual product story (original diagrams), **click-through operational workflow demo**, plain-language capabilities, founder story, and **TigerGRCi Community**.

Diagrams and layout are original. They are inspired by common enterprise GRC marketing patterns, not copied from other products.

## Local preview

```bash
cd website
npx --yes serve .
```

Use `http://` (not `file://`) so Community JSON loads.

## Founder photo

[`assets/sujan-chandra-ray.jpg`](assets/sujan-chandra-ray.jpg) appears in the hero and story sections.

## Community inbox (Formspree)

Set `FORMSPREE_ENDPOINT` in [`main.js`](main.js) to your Formspree form URL.

## Social profiles

Edit [`data/social.json`](data/social.json):

- `profiles.linkedin` — already set to your LinkedIn
- `profiles.facebook` — paste your Facebook profile or Page URL (optional; until set, Facebook buttons share this site)

Only `https://` URLs on allowlisted social hosts are accepted by the page.

## Secure-by-design (public site)

- CSP meta on every page; `_headers` for Cloudflare Pages (`frame-ancestors 'none'`)
- SVG diagrams parsed/sanitized (no script / event-handler injection)
- Mindmap labels via DOM `textContent`; sensitive stack/API copy redacted in UI
- Social + wall photo URL allowlists; Formspree honeypot; draft TTL 7 days
- Publish only a curated public tree: `node website/scripts/build-public-site.js` (excludes `scripts/`, `wrangler.toml`, `verification.json`)

## Zero-trust architecture (public site)

| Pillar | Implementation |
| --- | --- |
| Never trust third parties by default | Fonts self-hosted under `assets/fonts/` (no Google CDN) |
| Explicit verify at every boundary | `fetchTrustedJson` (same-origin, no redirects, schema check); Formspree URL assert |
| Least privilege | CSP `default-src 'none'`; `img-src 'self' data:`; wall photos = `assets/` only |
| Assume breach | Email never written to `localStorage`; 24h draft TTL; 12s submit cooldown |
| Microsegmentation | Formspree is the only allowed connect/form target; social hosts allowlisted |
| Isolation headers (Cloudflare) | COOP / CORP / COEP + Permissions-Policy in `_headers` |

## Moderated Community wall

[`data/community-wall.json`](data/community-wall.json) starts as `[]` (polished empty state on the page).

Example entry after you approve a real submission:

```json
[
  {
    "type": "review",
    "name": "Display name",
    "role": "Compliance practitioner",
    "rating": 5,
    "body": "Short public quote.",
    "photo": "assets/optional-avatar.jpg",
    "featured": false
  }
]
```

Set `"featured": true` and optional `"headline"` for a larger strip under the grid.

## Live free URLs (no paid domain)

| URL | Status |
| --- | --- |
| https://sujanchandray.github.io/tigergrci-site/ | Live (GitHub Pages) |
| https://tigergrci.sujanray.workers.dev/ | Live (Cloudflare Worker) |
| https://tigergrci.is-a.dev/ | Pending free subdomain PR: [is-a-dev/register#53266](https://github.com/is-a-dev/register/pull/53266) |

After that PR merges (usually minutes–a few days), set GitHub Pages custom domain to `tigergrci.is-a.dev` (CNAME file + Enforce HTTPS). Then update `canonical` / sitemap URLs in this folder and republish.

`.com` / `app.tigergrci.com` are **not** free — use the URLs above only.

## Deploy

- **GitHub Pages:** public site repo [tigergrci-site](https://github.com/sujanchandray/tigergrci-site) → https://sujanchandray.github.io/tigergrci-site/
- **Cloudflare Worker / Pages:** free `*.workers.dev` / `*.pages.dev` after `npx wrangler login`, then `node website/scripts/deploy-cloudflare-pages.js` (or workflow `.github/workflows/cloudflare-pages.yml` with `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID`).

## Content rules

- Advertise product outcomes and capabilities only.
- Do not publish backend, algorithms, eval seals, or build secrets.
- Do not invent Community wall posts.
- Prefer plain language over jargon.
