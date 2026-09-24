import type { EdgeAccessFacade } from './types.js';
import { EdgeAccessV2Shell } from './v2/shell.js';

export const EdgeAccessConfigFacade: EdgeAccessFacade = new EdgeAccessV2Shell();
