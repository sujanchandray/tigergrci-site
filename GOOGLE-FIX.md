# Fix Google visibility (Cloudflare primary)

GitHub Pages `Couldn't fetch` for sitemaps is a known Google limitation on `*.github.io`.  
**Primary public SEO URL is now:**

https://tigergrci.sujanray.workers.dev/

## Do this in Google Search Console (required — 10 minutes)

1. Open https://search.google.com/search-console
2. **Add property** → **URL prefix** → paste exactly:  
   `https://tigergrci.sujanray.workers.dev/`
3. Verify (HTML file method): the file  
   `https://tigergrci.sujanray.workers.dev/googlea36dc6fd400d4707.html`  
   is already on the site after deploy. Or use the meta-tag Google shows.
4. **Sitemaps** → submit: `sitemap.xml`
5. **URL Inspection** → `https://tigergrci.sujanray.workers.dev/` → **Request indexing**
6. Also request indexing for `/work-with-me.html` and `/privacy.html`
7. Update LinkedIn / GitHub **Website** field to the Cloudflare URL above

Ignore the old `github.io` sitemap **Couldn't fetch** row. That host cannot be forced to Success. Use the Cloudflare property instead.

## Share this URL publicly

https://tigergrci.sujanray.workers.dev/
