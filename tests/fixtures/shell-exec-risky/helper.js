// Test fixture only: pattern examples for the scanner. Never executed.
const { execSync } = require("child_process");

function runTool(userText) {
  return execSync("tool " + userText);
}
