import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { CTR_COMPARISON, clip, ctrBlocked, ctrClient, ctrCall, execOf, field, stdoutOf } from "./_ctr.js";

const DESCR =
  "Container/directory snapshots as a persistence and cross-instance data-carry channel";
const TARGET = "container.snapshotDirectory()/snapshotContainer() + ContainerStartupOptions restore";
const TAGS = ["container", "container:snapshot", "persistence", "leak"];

/**
 * W-CTR-09 — state that outlives the container that produced it.
 *
 * `snapshotDirectory()` / `snapshotContainer()` and the matching
 * `ContainerStartupOptions.directorySnapshots` / `containerSnapshot` are present on the
 * container handle in the shipped types but absent from the execute-commands
 * documentation page. They turn the container filesystem — which W-CTR-07 shows is
 * writable by exec'd processes — into durable, transferable state.
 *
 * Two questions, in order:
 *   1. **Persistence.** Does a file an exec'd process wrote at runtime survive a
 *      destroy + restore, i.e. is a filesystem implant durable across restarts?
 *   2. **Carry.** Does a snapshot taken by one Durable Object instance restore into a
 *      *different* instance? A snapshot handle is a plain JSON object; if possessing it
 *      is sufficient, then it is a capability that moves data between instances with no
 *      visible ACL — and W-CTR-02 gives an attacker the ability to write the payload.
 *
 * The marker is a benign run-tagged canary. Nothing is written outside /tmp.
 */
export const wCtr09: Probe = async ({ env, runId }) => {
  const ctr = ctrClient(env);
  if (!ctr)
    return ctrBlocked({
      testId: "W-CTR-09",
      description: DESCR,
      target: TARGET,
      runId,
      tags: TAGS,
      severity: "medium",
    });

  const marker = `flag{w-ctr-09-${runId.slice(0, 12)}}`;
  const dir = "/tmp/wulf";
  // Its own producer instance, not the shared one: this probe destroys and restarts the
  // container to test restore, and a wedged destroy on a shared Durable Object stalls
  // every probe queued behind it (observed in the first Wave 6 run).
  const producer = `wulf-ctr-snap-${runId.slice(0, 8)}`;
  const consumer = `wulf-ctr-restore-${runId.slice(0, 8)}`; // a distinct DO instance

  // 1. Write the runtime marker in the producer instance and snapshot it.
  const snap = await ctrCall(ctr, "snapshot", { dir, marker, name: `w-ctr-09-${runId.slice(0, 8)}`, full: true }, producer);
  const dirSnapshot = field(snap, "directory_snapshot") ?? null;
  const dirSnapshotError = field(snap, "directory_snapshot_error") ?? null;
  const fullSnapshot = field(snap, "container_snapshot") ?? null;
  const fullSnapshotError = field(snap, "container_snapshot_error") ?? null;
  const wroteMarker = stdoutOf(execOf(snap, "write")).includes(marker);

  // 2. Persistence: restore into the SAME instance and look for the marker.
  const sameInstance = dirSnapshot
    ? await ctrCall(ctr, "restore", { directory_snapshot: dirSnapshot, dir }, producer)
    : null;
  const sameLookup = sameInstance ? stdoutOf(execOf(sameInstance, "marker_lookup")) : "";
  const persisted = sameLookup.includes(marker);

  // 3. Carry: restore the same handle into a DIFFERENT instance.
  const otherInstance = dirSnapshot
    ? await ctrCall(ctr, "restore", { directory_snapshot: dirSnapshot, dir }, consumer)
    : null;
  const otherLookup = otherInstance ? stdoutOf(execOf(otherInstance, "marker_lookup")) : "";
  const carried = otherLookup.includes(marker);
  // Distinguishes a real restore from a plain fresh image start: the baseline file is
  // baked into the image, the marker is not.
  const otherSawBaseline = otherLookup.includes("flag{w-ctr-09-image-baseline}");

  // 4. Control: a fresh instance that restores NOTHING must not see the marker.
  const control = await ctrCall(ctr, "restore", { dir }, `wulf-ctr-control-${runId.slice(0, 8)}`);
  const controlLookup = stdoutOf(execOf(control, "marker_lookup"));
  const controlLeaked = controlLookup.includes(marker);

  const apiPresent = dirSnapshot !== null || fullSnapshot !== null;

  return base({
    test_id: "W-CTR-09",
    track: "worker",
    description: DESCR,
    target: TARGET,
    result: carried ? "accessible" : persisted ? "partial" : apiPresent ? "partial" : "blocked",
    severity: carried ? "high" : persisted ? "medium" : "informational",
    run_id: runId,
    tags: TAGS,
    details: {
      marker,
      wrote_runtime_marker: wroteMarker,
      directory_snapshot: dirSnapshot,
      directory_snapshot_error: dirSnapshotError,
      container_snapshot: fullSnapshot,
      container_snapshot_error: fullSnapshotError,
      snapshot_api_present: apiPresent,
      persisted_across_destroy_restore: persisted,
      same_instance_lookup: clip(sameLookup, 300),
      carried_to_other_instance: carried,
      other_instance_name: consumer,
      other_instance_lookup: clip(otherLookup, 300),
      other_instance_saw_image_baseline: otherSawBaseline,
      control_instance_leaked_marker: controlLeaked,
      control_lookup: clip(controlLookup, 300),
      note: "If the marker appears in the consumer instance and the control instance stays clean, a snapshot handle is a bearer capability: whoever holds the JSON handle can mount the data elsewhere. Combined with W-CTR-02 (attacker chooses what gets written) and W-CTR-06 (processes outlive the request), it turns the container filesystem into durable attacker-controlled state rather than per-request scratch.",
      recommendation:
        "Treat snapshot handles as secrets — never return one to a caller or store one where request-derived logic can reach it. Snapshot only directories the application owns, never a full container that has held a credential, and re-verify contents on restore rather than trusting the mount.",
      call_errors: {
        snapshot: snap.error ?? null,
        same: sameInstance?.error ?? null,
        other: otherInstance?.error ?? null,
        control: control.error ?? null,
      },
    },
    comparison: {
      aws_lambda:
        "N/A — no function-owned snapshot primitive. SnapStart snapshots are platform-managed, taken at Init, and not addressable from function code.",
      azure_functions: CTR_COMPARISON.azure_functions,
      gcp_functions: CTR_COMPARISON.gcp_functions,
    },
  });
};
