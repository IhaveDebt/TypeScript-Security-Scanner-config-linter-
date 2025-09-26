/**
 * Security Scanner (sec_scan.ts)
 *
 * - Scans JSON/YAML config files for common insecure settings.
 * - Example checks: debug=true, weak CORS, default credentials.
 *
 * Usage:
 *  ts-node src/sec_scan.ts scan ./configs
 */
import fs from 'fs/promises';
import path from 'path';

async function scanFile(file: string) {
  const txt = await fs.readFile(file, 'utf-8');
  const issues: string[] = [];
  if (/debug\s*:\s*true/i.test(txt) || /"debug"\s*:\s*true/i.test(txt)) issues.push('debug:true set');
  if (/cors.*\*\*/i.test(txt) || /allow_origin.*\*/i.test(txt)) issues.push('Open CORS policy');
  if (/password\s*:\s*["']?(admin|password|1234)/i.test(txt)) issues.push('Default/weak password found');
  return issues;
}

async function scanDir(dir: string) {
  const files = await fs.readdir(dir);
  for (const f of files) {
    const p = path.join(dir, f);
    const stat = await fs.stat(p);
    if (stat.isDirectory()) await scanDir(p);
    else if (f.endsWith('.json') || f.endsWith('.yml') || f.endsWith('.yaml')) {
      const issues = await scanFile(p);
      if (issues.length) console.log('ISSUES in', p, issues);
      else console.log('OK', p);
    }
  }
}

if (require.main === module) {
  const cmd = process.argv[2];
  if (cmd === 'scan') scanDir(process.argv[3] || '.');
  else console.log('Usage: scan <dir>');
}
