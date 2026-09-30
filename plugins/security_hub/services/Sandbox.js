// SPDX-License-Identifier: MIT
//
// Rules for the sandbox launcher (SandboxLauncher.qml, plan task 3.8,
// docs/ipc-protocol.md §4.7): checking the form before SANDBOX_RUN, the
// params it sends, and what a launch and a failure say. The daemon checks
// the paths again, and is the one that knows whether they exist. Free of
// QML so it can be tested with plain node.
.pragma library

var ErrorCode = {
  INVALID_PARAMS: -32602,
  MODULE_UNAVAILABLE: -32002,
  BACKEND_ERROR: -32006,
  NOT_IMPLEMENTED: -32007
}

// Launches remembered for "Run again", newest first.
var MAX_RUNS = 5

// "~" and "~/…" with the home directory, the rest as typed. Surrounding
// spaces (a pasted path with a newline after it) are dropped.
function expandPath(path, home) {
  var p = String(path || "").trim()
  if (home && (p === "~" || p.indexOf("~/") === 0)) return home + p.slice(1)
  return p
}

// Why `path` cannot be sent as `what` ("program" or "file"), or "".
function pathProblem(path, what) {
  if (path.charAt(0) !== "/")
    return what === "program" ? "Give the program's full path, such as /usr/bin/zathura."
      : "Give the file's full path, such as ~/Downloads/report.pdf."
  if (/[\u0000\n\r]/.test(path)) return "The " + what + "'s path has a line break in it."
  if (path.charAt(path.length - 1) === "/") return "The " + what + " is a directory; give a file."
  return ""
}

// Checks the form `{executable, target, shareNet}`. Returns `{params,
// error, warning}`: `params` for SANDBOX_RUN when it can be sent, else
// null, with `error` saying why (empty while nothing is typed).
function checkForm(form, home) {
  var f = form || {}
  var executable = expandPath(f.executable, home)
  var target = expandPath(f.target, home)
  var warning = f.shareNet ? "With network, the program can reach the internet and your local network." : ""
  if (executable === "") return { params: null, error: "", warning: warning }
  var problem = pathProblem(executable, "program")
  if (!problem && target !== "") problem = pathProblem(target, "file")
  if (problem) return { params: null, error: problem, warning: warning }
  var params = { executable: executable, share_net: !!f.shareNet }
  // The daemon binds the file at its own path; the program is told which
  // one to open.
  if (target !== "") {
    params.target_file = target
    params.args = [target]
  }
  return { params: params, error: "", warning: warning }
}

function baseName(path) {
  var p = String(path || "")
  var slash = p.lastIndexOf("/")
  return slash >= 0 ? p.slice(slash + 1) : p
}

// A launch this shell made: SANDBOX_RUN's params plus `pid` and `started_at`.
function addRun(runs, run, max) {
  var next = [run].concat(runs || [])
  return next.slice(0, max || MAX_RUNS)
}

function ago(ms) {
  var secs = Math.max(0, Math.round(ms / 1000))
  if (secs < 60) return "just now"
  var mins = Math.round(secs / 60)
  if (mins < 60) return mins + " min ago"
  return Math.round(mins / 60) + " h ago"
}

// "zathura with report.pdf, no network": what a launch was.
function runTitle(run) {
  if (!run) return ""
  var title = baseName(run.executable)
  if (run.target_file) title += " with " + baseName(run.target_file)
  return title + (run.share_net ? ", with network" : ", no network")
}

// "PID 4242 · just now"
function runDetail(run, now) {
  if (!run) return ""
  return "PID " + run.pid + " · " + ago(now - run.started_at)
}

// The form that starts `run` again.
function formFor(run) {
  return { executable: run.executable || "", target: run.target_file || "", shareNet: !!run.share_net }
}

function isUnavailable(error) {
  return !!error && (error.code === ErrorCode.MODULE_UNAVAILABLE || error.code === ErrorCode.NOT_IMPLEMENTED)
}

// What to say when SANDBOX_RUN failed. INVALID_PARAMS carries the daemon's
// reason ("executable /x: No such file or directory (os error 2)"). A
// missing module is not a failure of this launch: unavailableText says it.
function runErrorText(error) {
  if (!error || isUnavailable(error)) return ""
  var message = error.message || "unknown error"
  if (error.code === ErrorCode.INVALID_PARAMS) return "Not started: " + message.replace(/^invalid params: /, "")
  return "Could not start the sandbox: " + message
}

// Text for a launcher that cannot be used, or "". `error` is the last
// SANDBOX_RUN error.
function unavailableText(ready, moduleState, moduleDetail, error) {
  if (!ready) return "Not connected to omarchy-securityd"
  if (moduleState === "not_implemented") return "The sandbox is not available in this daemon"
  if (moduleState === "unavailable")
    return "The sandbox is not available" + (moduleDetail ? ": " + moduleDetail : "")
  if (isUnavailable(error)) return "The sandbox is not available: " + (error.message || "unknown error")
  return ""
}

if (typeof module !== "undefined") module.exports = {
  ErrorCode: ErrorCode, MAX_RUNS: MAX_RUNS, expandPath: expandPath, pathProblem: pathProblem,
  checkForm: checkForm, baseName: baseName, addRun: addRun, runTitle: runTitle, runDetail: runDetail,
  formFor: formFor, isUnavailable: isUnavailable, runErrorText: runErrorText, unavailableText: unavailableText
}
