import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

const WEB_APIS = [
  "fetch",
  "Request",
  "Response",
  "Headers",
  "URL",
  "URLPattern",
  "URLSearchParams",
  "WebSocket",
  "EventSource",
  "BroadcastChannel",
  "MessageChannel",
  "Worker",
  "SharedWorker",
  "ServiceWorker",
  "Notification",
  "PushManager",
  "ReadableStream",
  "WritableStream",
  "TransformStream",
  "CompressionStream",
  "DecompressionStream",
  "TextEncoder",
  "TextDecoder",
  "TextEncoderStream",
  "TextDecoderStream",
  "FormData",
  "Blob",
  "File",
  "FileReader",
  "ImageData",
  "ImageBitmap",
  "createImageBitmap",
  "OffscreenCanvas",
  "WebGLRenderingContext",
  "WebGL2RenderingContext",
  "GPUAdapter",
  "navigator.gpu",
  "Audio",
  "AudioContext",
  "MediaStream",
  "RTCPeerConnection",
  "indexedDB",
  "localStorage",
  "sessionStorage",
  "document",
  "window",
  "self",
  "location",
  "history",
  "alert",
  "prompt",
  "confirm",
  "performance.measureUserAgentSpecificMemory",
  "performance.now",
  "performance.timeOrigin",
  "crypto.subtle",
  "crypto.randomUUID",
  "crypto.getRandomValues",
];

function probe(path: string): { name: string; present: boolean; type: string } {
  const parts = path.split(".");
  let cur: unknown = globalThis;
  for (const p of parts) {
    if (cur == null) return { name: path, present: false, type: "undefined" };
    cur = (cur as Record<string, unknown>)[p];
  }
  return {
    name: path,
    present: cur !== undefined,
    type: typeof cur,
  };
}

export const wEnv05: Probe = async ({ runId }) => {
  const matrix = WEB_APIS.map(probe);
  const present = matrix.filter((m) => m.present).map((m) => m.name);
  const absent = matrix.filter((m) => !m.present).map((m) => m.name);

  return base({
    test_id: "W-ENV-05",
    track: "worker",
    description: "Web API availability matrix vs. browser standard",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      present_count: present.length,
      absent_count: absent.length,
      present,
      absent,
    },
  });
};
