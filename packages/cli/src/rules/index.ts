/**
 * Importing this module registers every rule via its module-scope
 * register*() side effect. Import it once before running the engine.
 */

// Config posture rules (§9)
import "./config/compat-flags.js";
import "./config/bindings.js";
import "./config/egress.js";
import "./config/wfp.js";
import "./config/supply-chain.js";

// Source rules (§8) — families A–G
import "./source/secrets.js"; // Family A
import "./source/injection.js"; // Family B
import "./source/state.js"; // Family C
import "./source/crypto.js"; // Family D
import "./source/fail-open.js"; // Family E
import "./source/resource.js"; // Family F
import "./source/binding-use.js"; // Family G
import "./source/request.js"; // Worker request layer
import "./source/cache.js"; // Cache API abuse
import "./source/handlers.js"; // Non-fetch handlers
import "./source/service-bindings.js"; // Service binding auth context

// Account rules (§11.2, §12) — live scan
import "./account/least-priv.js";
import "./account/drift.js";
import "./account/namespace.js";

// DAST probe rules — black-box, over the network (`wulf probe <url>`)
import "./probe/index.js";
