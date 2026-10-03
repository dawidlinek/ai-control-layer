// Build-time patch: allow an http:// OpenID issuer when OPENID_ALLOW_INSECURE_HTTP=true (demo only).
const fs = require('fs');

const file = process.argv[2];
const src = fs.readFileSync(file, 'utf8');
const needle = '[client.customFetch]: customFetch,\n      },\n    );';
const count = src.split(needle).length - 1;
if (count !== 1) {
  console.error(`patch-openid: expected exactly 1 discovery call to patch in ${file}, found ${count}`);
  process.exit(1);
}
const replacement =
  "[client.customFetch]: customFetch,\n        // ACL demo patch: plain-HTTP Keycloak on localhost\n        ...(process.env.OPENID_ALLOW_INSECURE_HTTP === 'true' ? { execute: [client.allowInsecureRequests] } : {}),\n      },\n    );";
fs.writeFileSync(file, src.replace(needle, replacement));
console.log('patch-openid: applied');
