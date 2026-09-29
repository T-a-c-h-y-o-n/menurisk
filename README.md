# Menu Risk

Free food-recall checker for restaurants: paste an ingredient list, match it
against active US FDA food recall data, and get a dated, source-linked record
of what is worth reviewing. Every match shows its reason and its source.

Live site: **https://menurisk.ai2eo.com**

## What is here

Static landing page (no build step, no framework):

```
index.html    landing + free scan form + result view
result.html   emailed result link target
styles.css    design tokens + components
script.js     form logic, result rendering, analytics events
config.js     runtime configuration
```

Plus `robots.txt`, `sitemap.xml`, `CNAME`, `404.html` and the legal pages
(`terms.html`, `privacy.html`, `disclaimer.html`).

## Notes

- The scan form works with or without the backend API. When the API is
  unreachable, requests are queued via the contact form provider and answered
  by email. Nothing is lost.
- US recalls only. Results are potential matches for human review, not a
  determination and not legal or compliance advice.

Contact: info@ai2eo.com
