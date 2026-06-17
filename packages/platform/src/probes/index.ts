import type { ProbeResult } from "@wulf/shared";
import type { Env } from "../dispatch.js";
import { pCap01 } from "./p-cap-01.js";
import { pDisp01 } from "./p-disp-01.js";
import { pDisp02 } from "./p-disp-02.js";
import { pDisp03 } from "./p-disp-03.js";
import { pLim01 } from "./p-lim-01.js";
import { pOut01 } from "./p-out-01.js";
import { pOut03 } from "./p-out-03.js";
import { pOut04 } from "./p-out-04.js";
import { pOut05 } from "./p-out-05.js";
import { pOut06 } from "./p-out-06.js";
import { pTen01 } from "./p-ten-01.js";
import { pTen02 } from "./p-ten-02.js";
import { pTen03 } from "./p-ten-03.js";

export interface ProbeCtx {
  env: Env;
  ctx: ExecutionContext;
  req: Request;
  runId: string;
}

export type Probe = (c: ProbeCtx) => Promise<ProbeResult>;

export const probes: Record<string, Probe> = {
  "P-DISP-01": pDisp01,
  "P-DISP-02": pDisp02,
  "P-DISP-03": pDisp03,
  "P-LIM-01": pLim01,
  "P-OUT-01": pOut01,
  "P-OUT-03": pOut03,
  "P-OUT-04": pOut04,
  "P-OUT-05": pOut05,
  "P-OUT-06": pOut06,
  "P-TEN-01": pTen01,
  "P-TEN-02": pTen02,
  "P-TEN-03": pTen03,
  "P-CAP-01": pCap01,
};
