const fs = require('fs');
const path = require('path');

const indexPath = path.join(__dirname, 'index.html');
const content = fs.readFileSync(indexPath, 'utf8');

const scriptSrc = 'https://cdn.jsdelivr.net/gh/dickhery/Ad-Network-Embed@3c07f3bd238b8d7fd516a95ba26cb568ba0e7b3f/ad-network-embed-bundled.js';
const projectId = 'Seed Vault';
const adType = 'Horizontal Banner Portrait';

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const pattern = new RegExp(
  `<script[^>]*src=["']${escapeRegex(scriptSrc)}["'][^>]*data-project-id=["']${escapeRegex(projectId)}["'][^>]*data-ad-type=["']${escapeRegex(adType)}["'][^>]*>\\s*<\\/script>`,
  's',
);

if (!pattern.test(content)) {
  console.error(
    'Error: Required ad script is missing from index.html. Deployment aborted. Please include the provided embed snippet.',
  );
  process.exit(1);
}

console.log('Ad script check passed.');
