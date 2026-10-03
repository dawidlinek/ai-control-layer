// TCP forwarder: 127.0.0.1:OIDC_LOCAL_PORT -> OIDC_UPSTREAM (host:port).
// Keycloak puts http://localhost:<port>/realms/acl into every token and discovery document; inside this container
// that address must reach the Keycloak container. Demo only (production: a real HTTPS issuer name).
const net = require('net');

const localPort = Number(process.env.OIDC_LOCAL_PORT || 8180);
const [host, port] = (process.env.OIDC_UPSTREAM || 'keycloak:8080').split(':');

function serve(address) {
  const server = net.createServer((client) => {
    const upstream = net.connect(Number(port), host);
    client.pipe(upstream);
    upstream.pipe(client);
    upstream.on('error', () => client.destroy());
    client.on('error', () => upstream.destroy());
  });
  server.on('error', (err) => console.error(`oidc-forward: ${address}: ${err.code || err.message}`));
  server.listen(localPort, address, () => console.log(`oidc-forward: ${address}:${localPort} -> ${host}:${port}`));
}

serve('127.0.0.1');
serve('::1');
