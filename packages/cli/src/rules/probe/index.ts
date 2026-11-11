/**
 * Importing this module registers every DAST probe rule via its module-scope
 * registerProbe() side effect. Rule order here is the execution order.
 */
import "./fingerprint.js"; // WF-DAST-FP-01, WF-DAST-ACCESS-01
import "./exposure.js"; // WF-DAST-EXPOSE-01..04 — static-asset leakage
import "./errors.js"; // WF-DAST-ERR-01..02 — exception / stack-trace disclosure
import "./cors.js"; // WF-DAST-CORS-01 — reflected Origin
import "./cache.js"; // WF-DAST-CACHE-01..02 — cache poisoning / cross-caller leak
import "./websocket.js"; // WF-DAST-WS-01 — unauthenticated DO/Agents WebSocket
