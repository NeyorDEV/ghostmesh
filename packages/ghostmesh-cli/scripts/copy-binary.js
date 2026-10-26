const fs = require('fs');
const path = require('path');

const binaryName = process.platform === 'win32' ? 'ghost-cli.exe' : 'ghost-cli';
const src = path.join(__dirname, '..', '..', '..', 'target', 'release', binaryName);
const destDir = path.join(__dirname, '..', 'bin');
const dest = path.join(destDir, binaryName);

if (!fs.existsSync(src)) {
  console.error(`Source binary not found at ${src}. Please run 'cargo build --release -p ghost-cli' first.`);
  process.exit(1);
}

if (!fs.existsSync(destDir)) {
  fs.mkdirSync(destDir, { recursive: true });
}

fs.copyFileSync(src, dest);
fs.chmodSync(dest, 0o755);
console.log(`Successfully bundled ${binaryName} into ${dest}`);
