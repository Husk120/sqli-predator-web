import { getAllScans } from './lib/store.ts';
(async () => {
  const scans = await getAllScans();
  console.log(JSON.stringify(scans, null, 2));
})();
