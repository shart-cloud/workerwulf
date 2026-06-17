import type { ProbeResult } from "@wulf/shared";
import type { Env } from "../index.js";
import { wEnv01 } from "./w-env-01.js";
import { wEnv02 } from "./w-env-02.js";
import { wEnv03 } from "./w-env-03.js";
import { wEnv04 } from "./w-env-04.js";
import { wEnv05 } from "./w-env-05.js";
import { wEnv06 } from "./w-env-06.js";
import { wBnd01 } from "./w-bnd-01.js";
import { wBnd02 } from "./w-bnd-02.js";
import { wBnd03 } from "./w-bnd-03.js";
import { wBnd04 } from "./w-bnd-04.js";
import { wBnd05 } from "./w-bnd-05.js";
import { wCache01 } from "./w-cache-01.js";
import { wCache02 } from "./w-cache-02.js";
import { wCache03 } from "./w-cache-03.js";
import { wErr01 } from "./w-err-01.js";
import { wErr02 } from "./w-err-02.js";
import { wErr03 } from "./w-err-03.js";
import { wErr04 } from "./w-err-04.js";
import { wNet01 } from "./w-net-01.js";
import { wNet02 } from "./w-net-02.js";
import { wNet03 } from "./w-net-03.js";
import { wNet04 } from "./w-net-04.js";
import { wNet05 } from "./w-net-05.js";
import { wNet06 } from "./w-net-06.js";
import { wIso03 } from "./w-iso-03.js";
import { wIso05 } from "./w-iso-05.js";
import { wIso06 } from "./w-iso-06.js";
import { wCfg05 } from "./w-cfg-05.js";
import { wCap01 } from "./w-cap-01.js";
import { wCap04 } from "./w-cap-04.js";
import { wCap03 } from "./w-cap-03.js";
import { wCap05 } from "./w-cap-05.js";
import { wObj01 } from "./w-obj-01.js";
import { wObj02 } from "./w-obj-02.js";
import { wObj03 } from "./w-obj-03.js";
import { wObj04 } from "./w-obj-04.js";
import { wReq01 } from "./w-req-01.js";
import { wRun01 } from "./w-run-01.js";
import { wRun02 } from "./w-run-02.js";
import { wRun03 } from "./w-run-03.js";
import { wRun04 } from "./w-run-04.js";
import { wRun05 } from "./w-run-05.js";
import { wRun06 } from "./w-run-06.js";
import { wSvc01 } from "./w-svc-01.js";
import { wSvc02 } from "./w-svc-02.js";
import { wSvc03 } from "./w-svc-03.js";
import { wSvc04 } from "./w-svc-04.js";
import { wWasm01 } from "./w-wasm-01.js";
import { wWasm02 } from "./w-wasm-02.js";
import { wWasm03 } from "./w-wasm-03.js";
import { wCtx01 } from "./w-ctx-01.js";
import { wCry01 } from "./w-cry-01.js";
import { wCry02 } from "./w-cry-02.js";
import { wCry03 } from "./w-cry-03.js";
import { wDyn01 } from "./w-dyn-01.js";
import { wDyn02 } from "./w-dyn-02.js";
import { wDyn03 } from "./w-dyn-03.js";
import { wDyn04 } from "./w-dyn-04.js";

export interface ProbeCtx {
  env: Env;
  ctx: ExecutionContext;
  req: Request;
  runId: string;
}

export type Probe = (c: ProbeCtx) => Promise<ProbeResult>;

export const probes: Record<string, Probe> = {
  "W-ENV-01": wEnv01,
  "W-ENV-02": wEnv02,
  "W-ENV-03": wEnv03,
  "W-ENV-04": wEnv04,
  "W-ENV-05": wEnv05,
  "W-ENV-06": wEnv06,
  "W-BND-01": wBnd01,
  "W-BND-02": wBnd02,
  "W-BND-03": wBnd03,
  "W-BND-04": wBnd04,
  "W-BND-05": wBnd05,
  "W-CACHE-01": wCache01,
  "W-CACHE-02": wCache02,
  "W-CACHE-03": wCache03,
  "W-ERR-01": wErr01,
  "W-ERR-02": wErr02,
  "W-ERR-03": wErr03,
  "W-ERR-04": wErr04,
  "W-NET-01": wNet01,
  "W-NET-02": wNet02,
  "W-NET-03": wNet03,
  "W-NET-04": wNet04,
  "W-NET-05": wNet05,
  "W-NET-06": wNet06,
  "W-ISO-03": wIso03,
  "W-ISO-05": wIso05,
  "W-ISO-06": wIso06,
  "W-CFG-05": wCfg05,
  "W-CAP-01": wCap01,
  "W-CAP-03": wCap03,
  "W-CAP-04": wCap04,
  "W-CAP-05": wCap05,
  "W-OBJ-01": wObj01,
  "W-OBJ-02": wObj02,
  "W-OBJ-03": wObj03,
  "W-OBJ-04": wObj04,
  "W-REQ-01": wReq01,
  "W-RUN-01": wRun01,
  "W-RUN-02": wRun02,
  "W-RUN-03": wRun03,
  "W-RUN-04": wRun04,
  "W-RUN-05": wRun05,
  "W-RUN-06": wRun06,
  "W-SVC-01": wSvc01,
  "W-SVC-02": wSvc02,
  "W-SVC-03": wSvc03,
  "W-SVC-04": wSvc04,
  "W-WASM-01": wWasm01,
  "W-WASM-02": wWasm02,
  "W-WASM-03": wWasm03,
  "W-CTX-01": wCtx01,
  "W-CRY-01": wCry01,
  "W-CRY-02": wCry02,
  "W-CRY-03": wCry03,
  "W-DYN-01": wDyn01,
  "W-DYN-02": wDyn02,
  "W-DYN-03": wDyn03,
  "W-DYN-04": wDyn04,
};
