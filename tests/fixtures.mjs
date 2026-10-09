// Test secrets and signers shared by the e2e suite and scripts/e2e.sh.
//   node tests/fixtures.mjs sources   → prints the WEBHOOK_SOURCES JSON the demo is published with
import { createHmac, createPrivateKey, createPublicKey, sign as edSign } from 'node:crypto';

export const SECRETS = {
  // GitHub's documented test secret: https://docs.github.com/webhooks/using-webhooks/validating-webhook-deliveries
  github: "It's a Secret to Everybody",
  twitch: 'twitch-test-secret-0123456789',
  stripe: 'whsec_stripe_test_secret_0123456789',
  // The Standard Webhooks spec's test secret, plus a second one to test rotation.
  app: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
  appOld: 'whsec_' + Buffer.from('an-older-secret-being-rotated-out').toString('base64'),
  custom: 'custom-secret-abcdef-0123456789',
  // Outbound endpoints
  endpoint: 'whsec_' + Buffer.from('outbound-endpoint-secret-24b!').toString('base64'),
};

// Discord: an ed25519 key from a fixed seed (RFC 8032 test 1's secret key).
const SEED = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex');
export const discordPrivate = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), SEED]),
  format: 'der',
  type: 'pkcs8',
});
export const DISCORD_PUBLIC_HEX = createPublicKey(discordPrivate).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');

export function sources() {
  return {
    github: { kind: 'github', secret: SECRETS.github },
    twitch: { kind: 'twitch', secret: SECRETS.twitch },
    stripe: { kind: 'stripe', secret: SECRETS.stripe },
    app: { kind: 'standard', secrets: [SECRETS.app, SECRETS.appOld] },
    discord: { kind: 'discord', public_key: DISCORD_PUBLIC_HEX },
    custom: {
      kind: 'hmac', secret: SECRETS.custom, header: 'X-Signature', prefix: 'sha256=', encoding: 'hex',
      id_header: 'X-Request-Id', type_header: 'X-Event-Type',
    },
  };
}

const hmac = (key, ...parts) => {
  const m = createHmac('sha256', key);
  for (const p of parts) m.update(p);
  return m.digest();
};
const standardKey = (secret) => Buffer.from(secret.replace(/^whsec_/, ''), 'base64');

/** Standard Webhooks: `v1,<base64>` over `<id>.<ts>.<body>`. */
export const signStandard = (secret, id, ts, body) => `v1,${hmac(standardKey(secret), `${id}.${ts}.`, body).toString('base64')}`;
export const signGithub = (secret, body) => `sha256=${hmac(secret, body).toString('hex')}`;
export const signTwitch = (secret, id, ts, body) => `sha256=${hmac(secret, id, ts, body).toString('hex')}`;
export const signStripe = (secret, t, body) => `t=${t},v1=${hmac(secret, `${t}.`, body).toString('hex')}`;
export const signHex = (secret, body) => hmac(secret, body).toString('hex');
export const signDiscord = (ts, body) => edSign(null, Buffer.from(ts + body), discordPrivate).toString('hex');

export function verifyStandard(secret, headers, body) {
  const id = headers['webhook-id'];
  const ts = headers['webhook-timestamp'];
  const expected = signStandard(secret, id, ts, body);
  return String(headers['webhook-signature']).split(' ').includes(expected);
}

if (process.argv[2] === 'sources') console.log(JSON.stringify(sources()));
