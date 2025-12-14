const fs = require('fs');
const path = require('path');

const indexPath = path.join(__dirname, 'index.html');
const content = fs.readFileSync(indexPath, 'utf8');

const scriptSrc = '/ad-network-embed-bundled.js';
const projectId = 'Seed Vault';
const adType = 'Horizontal Banner Portrait';

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const pattern = new RegExp(
  `<script[^>]*src=["']${escapeRegex(scriptSrc)}["'][^>]*data-project-id=["']${escapeRegex(projectId)}["'][^>]*data-ad-type=["']${escapeRegex(adType)}["'][^>]*>\\s*<\\/script>`,
  's',
);

const sriPattern = /integrity=["']sha256-[a-zA-Z0-9+/=]+["']/;

if (!pattern.test(content)) {
  console.error(
    'Error: Required ad script is missing from index.html. Deployment aborted. Please include the provided embed snippet.',
  );
  process.exit(1);
}

if (!sriPattern.test(content)) {
  console.error('Error: Ad script missing SRI integrity attribute.');
  process.exit(1);
}

console.log('Ad script check passed.');
