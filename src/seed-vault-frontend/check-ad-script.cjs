const fs = require('fs');
const path = require('path');

const indexPath = path.join(__dirname, 'index.html');
const content = fs.readFileSync(indexPath, 'utf8');

const scriptSrc = '/ad-network-embed-bundled.js';
const pattern = new RegExp(`<script[^>]*src=["']${scriptSrc}["'][^>]*>\\s*<\\/script>`, 's');

if (pattern.test(content)) {
  console.error(
    'Security check failed: third-party ad script must be removed from index.html to reduce attack surface.',
  );
  process.exit(1);
}

console.log('Ad script removal check passed.');
