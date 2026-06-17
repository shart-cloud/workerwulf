import type { ProbeResult } from "@wulf/shared";
import type { Env } from "../index.js";
import { dCap01 } from "./d-cap-01.js";
import { dCap02 } from "./d-cap-02.js";
import { dCap03 } from "./d-cap-03.js";
import { dNet01 } from "./d-net-01.js";
import { dNet02 } from "./d-net-02.js";
import { dNet03 } from "./d-net-03.js";
import { dReq01 } from "./d-req-01.js";
import { dCtx01 } from "./d-ctx-01.js";
import { dEnv06 } from "./d-env-06.js";
import { dBnd03 } from "./d-bnd-03.js";
import { dBnd04 } from "./d-bnd-04.js";
import { dBnd05 } from "./d-bnd-05.js";
import { dDo01 } from "./d-do-01.js";
import { dDo02 } from "./d-do-02.js";
import { dDo03 } from "./d-do-03.js";
import { dDo04 } from "./d-do-04.js";
import { dDo05 } from "./d-do-05.js";
import { dDyn04 } from "./d-dyn-04.js";

export interface ProbeCtx {
  env: Env;
  ctx: ExecutionContext;
  req: Request;
  runId: string;
}

export type Probe = (c: ProbeCtx) => Promise<ProbeResult>;

export const probes: Record<string, Probe> = {
  "D-CAP-01": dCap01,
  "D-CAP-02": dCap02,
  "D-CAP-03": dCap03,
  "D-NET-01": dNet01,
  "D-NET-02": dNet02,
  "D-NET-03": dNet03,
  "D-REQ-01": dReq01,
  "D-CTX-01": dCtx01,
  "D-ENV-06": dEnv06,
  "D-BND-03": dBnd03,
  "D-BND-04": dBnd04,
  "D-BND-05": dBnd05,
  "D-DO-01": dDo01,
  "D-DO-02": dDo02,
  "D-DO-03": dDo03,
  "D-DO-04": dDo04,
  "D-DO-05": dDo05,
  "D-DYN-04": dDyn04,
};
