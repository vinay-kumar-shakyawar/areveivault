// Google Tag Manager bootstrap. Kept in a file (not inline) so the CSP needs no 'unsafe-inline'.
// Only shipped when the build runs with GTM_ID set; see build.mjs.
window.dataLayer = window.dataLayer || [];
function gtag(){dataLayer.push(arguments);}
gtag('js', new Date());
// The container's Page View triggers wait for this event.
dataLayer.push({ 'gtm.start': new Date().getTime(), event: 'gtm.js' });
