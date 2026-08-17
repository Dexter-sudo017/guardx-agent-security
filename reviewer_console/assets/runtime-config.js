"use strict";

// Keep the value empty when the frontend and GuardX API share one origin.
// For a split deployment, set this to the public API origin, for example:
// https://api.guardx.example.com
window.GUARDX_RUNTIME_CONFIG = Object.freeze({
  apiBaseUrl: ""
});
