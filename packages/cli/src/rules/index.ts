/**
 * Importing this module registers every rule: config, source and account rules
 * from @wulf/analyze, then the CLI's DAST probe rules.
 */
import "@wulf/analyze";

// DAST probe rules — black-box, over the network (`wulf probe <url>`)
import "./probe/index.js";
