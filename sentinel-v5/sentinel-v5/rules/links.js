// SENTINEL v5 — Link & URL Analysis

export function analyseLinks(html, bodyText) {
  const findings = [];

  // Extract all hrefs
  const hrefRegex = /href=["']([^"']+)["']/gi;
  const urls = [];
  let m;
  while ((m = hrefRegex.exec(html)) !== null) {
    try { urls.push(new URL(m[1])); } catch {}
  }

  if (!urls.length) return findings;

  // IP-based URLs
  const ipUrls = urls.filter(u => /^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname));
  if (ipUrls.length) {
    findings.push({
      type:"IP_URL", severity:"CRITICAL",
      title:`${ipUrls.length} link(s) use raw IP addresses`,
      detail:`Links like http://192.168.x.x/ hide the real destination. Legitimate websites always use domain names. IP-based links are almost exclusively used in phishing and malware distribution.`,
      advice:"Never click links with IP addresses instead of domain names."
    });
  }

  // Shortened URLs
  const SHORTENERS = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","short.io","rebrand.ly","tiny.cc","is.gd","buff.ly","cutt.ly","rb.gy"];
  const shortened = urls.filter(u => SHORTENERS.includes(u.hostname));
  if (shortened.length) {
    findings.push({
      type:"SHORTENED_URL", severity:"HIGH",
      title:`${shortened.length} shortened/obfuscated URL(s)`,
      detail:`Shortened URLs (${shortened.map(u=>u.hostname).join(", ")}) hide the real destination. Attackers use them to disguise malicious links as innocent ones.`,
      advice:"Never click shortened URLs in emails you didn't expect. Expand them first at checkshorturl.com."
    });
  }

  // Suspicious TLDs
  const SUSP_TLDS = [".tk",".ml",".ga",".cf",".gq",".pw",".top",".xyz",".click",".link",".loan",".work",".date",".racing",".download",".stream"];
  const suspTld = urls.filter(u => SUSP_TLDS.some(tld => u.hostname.endsWith(tld)));
  if (suspTld.length) {
    findings.push({
      type:"SUSPICIOUS_TLD", severity:"HIGH",
      title:"Links use suspicious domain extensions",
      detail:`${suspTld.length} link(s) use TLDs (${[...new Set(suspTld.map(u => "."+u.hostname.split(".").pop()))].join(", ")}) commonly associated with spam and phishing campaigns due to being free or extremely cheap to register.`,
      advice:"Be very cautious of links using these domain extensions."
    });
  }

  // Lookalike domains
  const BRANDS = ["paypal","amazon","apple","google","microsoft","netflix","facebook","instagram","twitter","linkedin","dropbox","adobe","chase","wellsfargo","citibank","hsbc","dhl","fedex","ups"];
  for (const brand of BRANDS) {
    const lookalike = urls.find(u => {
      const h = u.hostname.replace(/^www\./,"");
      return h.includes(brand) && h !== `${brand}.com` && !h.endsWith(`.${brand}.com`);
    });
    if (lookalike) {
      findings.push({
        type:"LOOKALIKE_DOMAIN", severity:"CRITICAL",
        title:`Lookalike domain impersonates ${brand.toUpperCase()}`,
        detail:`Link goes to "${lookalike.hostname}" which mimics ${brand}'s real domain. This is a fake website designed to steal your login credentials or payment information.`,
        advice:`The real ${brand} website would never be at this address. Do not click.`
      });
    }
  }

  // @ in URL (obfuscation trick)
  const atUrls = urls.filter(u => u.href.includes("@"));
  if (atUrls.length) {
    findings.push({
      type:"URL_AT_TRICK", severity:"CRITICAL",
      title:"URL uses @ to hide real destination",
      detail:"URLs containing @ are a known obfuscation trick. Everything before the @ is ignored and the real destination is after it. E.g. http://google.com@evil.com goes to evil.com.",
      advice:"This is almost certainly a malicious link designed to look legitimate."
    });
  }

  // Link text vs href mismatch
  const linkPairs = [];
  const fullLinkRegex = /<a[^>]+href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi;
  let lm;
  while ((lm = fullLinkRegex.exec(html)) !== null) {
    const href = lm[1], text = lm[2].replace(/<[^>]+>/g,"").trim();
    if (text.startsWith("http") && !href.includes(text.split("/")[2])) {
      linkPairs.push({ href, text });
    }
  }
  if (linkPairs.length) {
    findings.push({
      type:"LINK_TEXT_MISMATCH", severity:"HIGH",
      title:"Link text doesn't match actual destination",
      detail:`${linkPairs.length} link(s) display a different URL than where they actually go. For example, showing "paypal.com" but linking to a completely different website.`,
      advice:"Never trust the text of a link — always check where it actually goes before clicking."
    });
  }

  // Too many redirects (multiple slashes after domain)
  const redirectUrls = urls.filter(u => (u.pathname.match(/\//g)||[]).length > 4);
  if (redirectUrls.length > 2) {
    findings.push({
      type:"DEEP_REDIRECT", severity:"LOW",
      title:"Links contain deeply nested paths",
      detail:"Some links have unusually complex paths that may go through multiple redirects before reaching the final destination.",
      advice:"Be cautious — complex URL paths can hide malicious redirects."
    });
  }

  return findings;
}
