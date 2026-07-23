const tsNodeRegister = require('C:/Users/kushg/AppData/Roaming/npm/node_modules/ts-node/register');
const store = require('./lib/store.ts');
// Access the internal map via global
const storeMap = global.__scansStore;
if (storeMap) {
  console.log('Local scan store size:', storeMap.size);
  const entries = [];
  for (const [id, scan] of storeMap.entries()) {
    entries.push({ id, ...scan });
  }
  console.log('Stored scans:', JSON.stringify(entries, null, 2));
} else {
  console.log('No local scan store found.');
}
// Also try getAllScans
if (typeof store.getAllScans === 'function') {
  (async () => {
    const scans = await store.getAllScans();
    console.log('From getAllScans:', JSON.stringify(scans, null, 2));
  })();
}
