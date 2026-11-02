// Test fixture only: safe argument-list execution. Never executed.
const { execFile } = require("child_process");

function runTool(name) {
  return execFile("tool", ["--name", name]);
}
