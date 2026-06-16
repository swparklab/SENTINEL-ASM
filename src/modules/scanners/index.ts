/** 점검 엔진 레지스트리 (설계 §4). */
import type { ScanModule } from '../../types.js';
import type { Scanner } from './types.js';
import { asmScanner } from './asm.js';
import { configScanner } from './config.js';
import { cveScanner } from './cve.js';
import { dastScanner } from './dast.js';

export const SCANNERS: Record<ScanModule, Scanner> = {
  asm: asmScanner,
  config: configScanner,
  cve: cveScanner,
  dast: dastScanner,
};

export { EgressGuard } from './egress.js';
export type { ScanContext } from './types.js';
