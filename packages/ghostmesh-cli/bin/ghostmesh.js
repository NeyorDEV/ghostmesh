#!/usr/bin/env node

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const binaryName = process.platform === 'win32' ? 'ghost-cli.exe' : 'ghost-cli';

// Potential binary locations (local bundled, dev workspace, or home cache)
const candidatePaths = [
  path.join(__dirname, binaryName),
  path.join(__dirname, '..', '..', '..', 'target', 'release', binaryName),
  path.join(__dirname, '..', '..', '..', 'target', 'debug', binaryName),
  path.join(os.homedir(), '.ghostmesh', 'bin', binaryName),
];


let binaryPath = candidatePaths.find(p => fs.existsSync(p));

if (!binaryPath) {
  console.error(`\x1b[31m[GhostMesh]\x1b[0m Native binary not found (${binaryName}).`);
  console.error(`Looking in:`);
  candidatePaths.forEach(p => console.error(`  - ${p}`));
  console.error(`\nPlease build the Rust binary with: \x1b[36mcargo build --release -p ghost-cli\x1b[0m`);
  process.exit(1);
}

const result = spawnSync(binaryPath, process.argv.slice(2), {
  stdio: 'inherit',
  env: process.env,
});

if (result.error) {
  console.error(`\x1b[31m[GhostMesh]\x1b[0m Execution error:`, result.error.message);
  process.exit(1);
}

process.exit(result.status ?? 0);
