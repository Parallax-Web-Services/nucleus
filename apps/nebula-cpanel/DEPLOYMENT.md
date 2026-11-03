# cPanel plugin installation record

The reviewed `0.1.3-dev` package was installed on Iota with cPanel & WHM `11.110.0.154` on 2026-11-02. The host check, installation, repeated same-install idempotence check, and four own registration outputs passed. The WHM CGI and cPanel LivePHP landing pages rendered successfully under an unprivileged account.

The vendor registration notification was explicitly authorized. Delivery was not verified.

The accepted archive SHA-256 is `768201bba2ac272fa975398614820b9f18b8bca28d53702105e853946d02f035`. All 13 packaged source files are retained here byte for byte. Their preparation-time README is unchanged; this installation record is separate from that archive. The 247 offline fixture assertions passed before installation.

This plugin provides navigation to the NEBULA panel. NEXUS sign-in and NEBULA determine access there. It does not bind hosting accounts, transfer panel sessions or credentials, or provision Kubernetes resources. Real host profiles, operation receipts, generated archives, and private files are not retained in this source tree.

From a fresh source checkout, create an empty `dist/` directory before running `sh scripts/package.sh`. Generated distributions remain outside the retained source.
