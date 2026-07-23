import { getAllScans } from './lib/store.ts';

async function main() {
  const scans = await getAllScans();
  console.log(JSON.stringify(scans, null, 2));
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
