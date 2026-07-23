import { getAllScans } from './lib/store';
(async () => {
  const scans = await getAllScans();
  console.log(JSON.stringify(scans, null, 2));
})();
