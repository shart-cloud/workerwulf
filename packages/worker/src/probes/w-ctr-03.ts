import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { CTR_COMPARISON, clip, ctrBlocked, ctrClient, ctrStdin, field, payloadBytes, seedFrom, sha256Hex } from "./_ctr.js";

const DESCR =
  "Request body streamed directly into a container process's stdin — fidelity, streaming, and attacker-chosen demuxer";
const TARGET = "ctx.container.exec(cmd, { stdin: request.body })";
const TAGS = ["container", "container:exec", "container:stdin", "injection"];

/** 64x64 RGB24 = 12288 bytes — a complete rawvideo frame, no container header needed. */
const FRAME_W = 64;
const FRAME_H = 64;
const FRAME_BYTES = FRAME_W * FRAME_H * 3;

/**
 * W-CTR-03 — the shape the wave exists for.
 *
 * A Worker can hand an inbound HTTP request body to a Linux process's stdin without
 * ever buffering it in the isolate: `exec(cmd, { stdin: request.body })`. Three
 * things are established, in order:
 *
 *  1. **Fidelity + streaming.** A pseudo-random payload through `cat` must come back
 *     byte-identical (SHA-256 in == SHA-256 out), including when sent as a chunked
 *     ReadableStream with no Content-Length. This proves the isolate is a pipe, not a
 *     parser: no size accounting, no inspection, no opportunity for a WAF-style check.
 *  2. **A real consumer.** The demo's pipeline — bytes in, ffmpeg, encoded image out —
 *     reproduced with a rawvideo frame transcoded to WebP. Verified by the RIFF/WEBP
 *     magic on stdout, not by ffmpeg's exit code alone.
 *  3. **Attacker-chosen demuxer.** When the Worker lets ffmpeg auto-probe the input
 *     format (`-i pipe:0`, the natural way to write it), the *payload* chooses the
 *     demuxer. A playlist payload asks the concat demuxer to open a container-local
 *     path — the classic media-parser local-file-read class, now reachable from an
 *     unauthenticated HTTP body at the edge. Recorded as observed, whether or not
 *     ffmpeg's `-safe` default holds.
 */
export const wCtr03: Probe = async ({ env, runId }) => {
  const ctr = ctrClient(env);
  if (!ctr)
    return ctrBlocked({
      testId: "W-CTR-03",
      description: DESCR,
      target: TARGET,
      runId,
      tags: TAGS,
      severity: "high",
    });

  const seed = seedFrom(runId);

  // --- 1a. Fidelity through `cat`, with a declared Content-Length ---------------
  const payload = payloadBytes(256 * 1024, seed);
  const sentSha = await sha256Hex(payload);
  const catCall = await ctrStdin(ctr, ["cat"], payload as unknown as BodyInit);
  const catSha = field(catCall, "stdout_sha256");
  const byteExact = catSha === sentSha && field(catCall, "stdout_bytes") === payload.byteLength;

  // --- 1b. Same, but chunked: a ReadableStream with no Content-Length -----------
  const chunk = payloadBytes(64 * 1024, seed ^ 0x5bf03635);
  const chunks = 4;
  const streamed = new ReadableStream<Uint8Array>({
    start(controller) {
      for (let i = 0; i < chunks; i++) controller.enqueue(chunk);
      controller.close();
    },
  });
  const streamedSha = await sha256Hex(
    (() => {
      const joined = new Uint8Array(chunk.byteLength * chunks);
      for (let i = 0; i < chunks; i++) joined.set(chunk, i * chunk.byteLength);
      return joined;
    })(),
  );
  const streamCall = await ctrStdin(ctr, ["cat"], streamed as unknown as BodyInit);
  const streamExact =
    field(streamCall, "stdout_sha256") === streamedSha &&
    field(streamCall, "stdout_bytes") === chunk.byteLength * chunks;

  // --- 2. The demo: rawvideo frame -> ffmpeg -> WebP ---------------------------
  const frame = payloadBytes(FRAME_BYTES, seed ^ 0x1f2e3d4c);
  const ffmpegCall = await ctrStdin(
    ctr,
    [
      "ffmpeg",
      "-hide_banner",
      "-loglevel", "info",
      "-f", "rawvideo",
      "-pix_fmt", "rgb24",
      "-s", `${FRAME_W}x${FRAME_H}`,
      "-i", "pipe:0",
      "-frames:v", "1",
      "-f", "webp",
      "pipe:1",
    ],
    frame as unknown as BodyInit,
  );
  const magic = String(field(ffmpegCall, "stdout_magic_hex") ?? "");
  // "RIFF" = 52494646, "WEBP" at offset 8 = 57454250
  const transcoded = magic.startsWith("52494646") && magic.slice(16, 24) === "57454250";

  // --- 3. Attacker-chosen demuxer: the payload picks the parser ----------------
  // The Worker did NOT name a format here — `-i pipe:0` auto-probes, which is the
  // natural way to write "accept an image from the user". The payload is a playlist.
  const playlist = new TextEncoder().encode(
    "ffconcat version 1.0\nfile /etc/hostname\nfile /proc/self/environ\n",
  );
  const demuxCall = await ctrStdin(
    ctr,
    ["ffmpeg", "-hide_banner", "-loglevel", "verbose", "-i", "pipe:0", "-f", "null", "-"],
    playlist as unknown as BodyInit,
  );
  const demuxStderr = String(field(demuxCall, "stderr_tail") ?? "");
  const concatSelected = /concat/i.test(demuxStderr);
  const localPathTouched = /(\/etc\/hostname|\/proc\/self\/environ)/.test(demuxStderr);
  const safeModeHeld = /unsafe file name|Unsafe file name/.test(demuxStderr);

  const pipeWorks = byteExact && streamExact;
  const result = pipeWorks && transcoded ? "accessible" : pipeWorks || transcoded ? "partial" : "blocked";

  return base({
    test_id: "W-CTR-03",
    track: "worker",
    description: DESCR,
    target: TARGET,
    result,
    // The stdin channel itself is the exposure: unfiltered attacker bytes reach a
    // native parser. The severity is carried by what that parser will do with them.
    severity: localPathTouched && !safeModeHeld ? "high" : pipeWorks ? "medium" : "informational",
    run_id: runId,
    tags: TAGS,
    details: {
      // 1
      sent_bytes: payload.byteLength,
      sent_sha256: sentSha,
      returned_sha256: catSha ?? null,
      byte_exact_round_trip: byteExact,
      chunked_stream_bytes: chunk.byteLength * chunks,
      chunked_stream_exact: streamExact,
      chunked_declared_content_length: false,
      // 2
      ffmpeg_frame_bytes: FRAME_BYTES,
      ffmpeg_exit_code: field(ffmpegCall, "exit_code") ?? null,
      ffmpeg_stdout_bytes: field(ffmpegCall, "stdout_bytes") ?? 0,
      ffmpeg_stdout_magic_hex: magic,
      ffmpeg_produced_webp: transcoded,
      ffmpeg_stderr_tail: clip(String(field(ffmpegCall, "stderr_tail") ?? ""), 700),
      ffmpeg_duration_ms: field(ffmpegCall, "duration_ms") ?? null,
      // 3
      demuxer_autoprobe_payload: "ffconcat playlist referencing /etc/hostname and /proc/self/environ",
      demuxer_concat_selected: concatSelected,
      demuxer_local_path_touched: localPathTouched,
      demuxer_safe_mode_held: safeModeHeld,
      demuxer_exit_code: field(demuxCall, "exit_code") ?? null,
      demuxer_stderr_tail: clip(demuxStderr, 900),
      note: "The isolate never sees the bytes. `exec(cmd, { stdin: request.body })` connects an unauthenticated HTTP body to a native parser with no interposition point — no equivalent of the Track-4 AST validator, no scan hook, and no size accounting on the isolate side. Whatever CVE class lives in the chosen consumer is now edge-reachable, and stage 3 shows the payload can also choose *which* consumer runs when the Worker lets the format be auto-probed.",
      recommendation:
        "Pin the input format explicitly (`-f rawvideo`, `-f mjpeg`, …) so the payload cannot select a demuxer; cap the body before it reaches exec(); run the consumer with `-safe 1`, no filesystem access it does not need, and a non-root `user`.",
      call_errors: {
        cat: catCall.error ?? null,
        stream: streamCall.error ?? null,
        ffmpeg: ffmpegCall.error ?? null,
        demux: demuxCall.error ?? null,
      },
    },
    comparison: CTR_COMPARISON,
  });
};
