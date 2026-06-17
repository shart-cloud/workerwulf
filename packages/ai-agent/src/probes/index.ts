import type { ProbeResult } from "@wulf/shared";
import type { Env } from "../index.js";
import { aiInj01 } from "./ai-inj-01.js";
import { aiInj02 } from "./ai-inj-02.js";
import { aiInj03 } from "./ai-inj-03.js";
import { aiInj04 } from "./ai-inj-04.js";
import { aiInj05 } from "./ai-inj-05.js";
import { aiInj06 } from "./ai-inj-06.js";
import { aiInj07 } from "./ai-inj-07.js";
import { aiInj08 } from "./ai-inj-08.js";
import { aiInj09 } from "./ai-inj-09.js";
import { aiInj10 } from "./ai-inj-10.js";
import { aiInj11 } from "./ai-inj-11.js";
import { aiInj12 } from "./ai-inj-12.js";
import { aiInj13 } from "./ai-inj-13.js";
import { aiInj14 } from "./ai-inj-14.js";

export interface ProbeCtx {
  env: Env;
  ctx: ExecutionContext;
  req: Request;
  runId: string;
}

export type Probe = (c: ProbeCtx) => Promise<ProbeResult>;

export const probes: Record<string, Probe> = {
  "AI-INJ-01": aiInj01,
  "AI-INJ-02": aiInj02,
  "AI-INJ-03": aiInj03,
  "AI-INJ-04": aiInj04,
  "AI-INJ-05": aiInj05,
  "AI-INJ-06": aiInj06,
  "AI-INJ-07": aiInj07,
  "AI-INJ-08": aiInj08,
  "AI-INJ-09": aiInj09,
  "AI-INJ-10": aiInj10,
  "AI-INJ-11": aiInj11,
  "AI-INJ-12": aiInj12,
  "AI-INJ-13": aiInj13,
  "AI-INJ-14": aiInj14,
};