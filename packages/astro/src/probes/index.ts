import type { ProbeResult } from "@wulf/shared";
import type { Env } from "../index.js";
import { aIsland01 } from "./a-island-01.js";
import { aIsland02 } from "./a-island-02.js";
import { aIsland03 } from "./a-island-03.js";
import { aIsland04 } from "./a-island-04.js";
import { aAction01 } from "./a-action-01.js";
import { aAction02 } from "./a-action-02.js";
import { aAction03 } from "./a-action-03.js";
import { aForm01 } from "./a-form-01.js";
import { aForm02 } from "./a-form-02.js";

export interface ProbeCtx {
  env: Env;
  ctx: ExecutionContext;
  req: Request;
  runId: string;
}

export type Probe = (c: ProbeCtx) => Promise<ProbeResult>;

export const probes: Record<string, Probe> = {
  "A-ISLAND-01": aIsland01,
  "A-ISLAND-02": aIsland02,
  "A-ISLAND-03": aIsland03,
  "A-ISLAND-04": aIsland04,
  "A-ACTION-01": aAction01,
  "A-ACTION-02": aAction02,
  "A-ACTION-03": aAction03,
  "A-FORM-01": aForm01,
  "A-FORM-02": aForm02,
};
