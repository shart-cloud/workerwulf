import type { ProbeResult } from "@wulf/shared";
import type { Env } from "../index.js";
import { doSql01 } from "./do-sql-01.js";
import { doSql02 } from "./do-sql-02.js";
import { doSql03 } from "./do-sql-03.js";
import { doSql04 } from "./do-sql-04.js";
import { doSql05 } from "./do-sql-05.js";
import { doSql06 } from "./do-sql-06.js";
import { doSq301 } from "./do-sq3-01.js";
import { doSq302 } from "./do-sq3-02.js";
import { doSq303 } from "./do-sq3-03.js";
import { doSq304 } from "./do-sq3-04.js";
import { doSq305 } from "./do-sq3-05.js";
import { doSq306 } from "./do-sq3-06.js";
import { doSq307 } from "./do-sq3-07.js";
import { doSq308 } from "./do-sq3-08.js";
import { doDyn01 } from "./do-dyn-01.js";
import { doDyn02 } from "./do-dyn-02.js";
import { doDyn03 } from "./do-dyn-03.js";
import { doDyn04 } from "./do-dyn-04.js";
import { doDyn05 } from "./do-dyn-05.js";
import { doMon01 } from "./do-mon-01.js";
import { doMon02 } from "./do-mon-02.js";
import { doMon03 } from "./do-mon-03.js";
import { doIdor01 } from "./do-idor-01.js";
import { doIdor02 } from "./do-idor-02.js";
import { doIdor03 } from "./do-idor-03.js";

export interface ProbeCtx {
  env: Env;
  ctx: ExecutionContext;
  req: Request;
  runId: string;
}

export type Probe = (c: ProbeCtx) => Promise<ProbeResult>;

export const probes: Record<string, Probe> = {
  "DO-SQL-01": doSql01,
  "DO-SQL-02": doSql02,
  "DO-SQL-03": doSql03,
  "DO-SQL-04": doSql04,
  "DO-SQL-05": doSql05,
  "DO-SQL-06": doSql06,
  "DO-SQ3-01": doSq301,
  "DO-SQ3-02": doSq302,
  "DO-SQ3-03": doSq303,
  "DO-SQ3-04": doSq304,
  "DO-SQ3-05": doSq305,
  "DO-SQ3-06": doSq306,
  "DO-SQ3-07": doSq307,
  "DO-SQ3-08": doSq308,
  "DO-DYN-01": doDyn01,
  "DO-DYN-02": doDyn02,
  "DO-DYN-03": doDyn03,
  "DO-DYN-04": doDyn04,
  "DO-DYN-05": doDyn05,
  "DO-MON-01": doMon01,
  "DO-MON-02": doMon02,
  "DO-MON-03": doMon03,
  "DO-IDOR-01": doIdor01,
  "DO-IDOR-02": doIdor02,
  "DO-IDOR-03": doIdor03,
};
