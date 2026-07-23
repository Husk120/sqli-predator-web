const tsNodeRegister = require('C:/Users/kushg/AppData/Roaming/npm/node_modules/ts-node/register');
const { getAllScans } = require('./lib/store.ts');
(async () => {
  const scans = await getAllScans();
  console.log(JSON.stringify(scans, null, 2));
})();
