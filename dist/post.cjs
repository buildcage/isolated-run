//#region \0rolldown/runtime.js
var __create = Object.create, __defProp = Object.defineProperty, __getOwnPropDesc = Object.getOwnPropertyDescriptor, __getOwnPropNames = Object.getOwnPropertyNames, __getProtoOf = Object.getPrototypeOf, __hasOwnProp = Object.prototype.hasOwnProperty, __copyProps = (to, from, except, desc) => {
	if (from && typeof from == "object" || typeof from == "function") for (var keys = __getOwnPropNames(from), i = 0, n = keys.length, key; i < n; i++) key = keys[i], !__hasOwnProp.call(to, key) && key !== except && __defProp(to, key, {
		get: ((k) => from[k]).bind(null, key),
		enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
	});
	return to;
}, __toESM = (mod, isNodeMode, target) => (target = mod == null ? {} : __create(__getProtoOf(mod)), __copyProps(isNodeMode || !mod || !mod.__esModule || !__hasOwnProp.call(mod, "default") ? __defProp(target, "default", {
	value: mod,
	enumerable: !0
}) : target, mod));
//#endregion
let node_child_process = require("node:child_process"), node_url = require("node:url"), os = require("os");
os = __toESM(os, 1);
let fs = require("fs");
fs = __toESM(fs, 1);
let path = require("path");
path = __toESM(path, 1);
let events = require("events");
events = __toESM(events, 1);
let node_crypto = require("node:crypto"), child_process = require("child_process");
child_process = __toESM(child_process, 1), require("timers");
let node_path = require("node:path"), node_fs = require("node:fs");
//#endregion
//#region node_modules/.pnpm/@actions+core@3.0.1/node_modules/@actions/core/lib/summary.js
var __awaiter$6 = function(thisArg, _arguments, P, generator) {
	function adopt(value) {
		return value instanceof P ? value : new P(function(resolve) {
			resolve(value);
		});
	}
	return new (P ||= Promise)(function(resolve, reject) {
		function fulfilled(value) {
			try {
				step(generator.next(value));
			} catch (e) {
				reject(e);
			}
		}
		function rejected(value) {
			try {
				step(generator.throw(value));
			} catch (e) {
				reject(e);
			}
		}
		function step(result) {
			result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
		}
		step((generator = generator.apply(thisArg, _arguments || [])).next());
	});
};
const { access, appendFile, writeFile } = fs.promises, SUMMARY_ENV_VAR = "GITHUB_STEP_SUMMARY";
new class {
	constructor() {
		this._buffer = "";
	}
	filePath() {
		return __awaiter$6(this, void 0, void 0, function* () {
			if (this._filePath) return this._filePath;
			let pathFromEnv = process.env[SUMMARY_ENV_VAR];
			if (!pathFromEnv) throw Error(`Unable to find environment variable for $${SUMMARY_ENV_VAR}. Check if your runtime environment supports job summaries.`);
			try {
				yield access(pathFromEnv, fs.constants.R_OK | fs.constants.W_OK);
			} catch {
				throw Error(`Unable to access summary file: '${pathFromEnv}'. Check if the file has correct read/write permissions.`);
			}
			return this._filePath = pathFromEnv, this._filePath;
		});
	}
	wrap(tag, content, attrs = {}) {
		let htmlAttrs = Object.entries(attrs).map(([key, value]) => ` ${key}="${value}"`).join("");
		return content ? `<${tag}${htmlAttrs}>${content}</${tag}>` : `<${tag}${htmlAttrs}>`;
	}
	write(options) {
		return __awaiter$6(this, void 0, void 0, function* () {
			let overwrite = !!options?.overwrite, filePath = yield this.filePath();
			return yield (overwrite ? writeFile : appendFile)(filePath, this._buffer, { encoding: "utf8" }), this.emptyBuffer();
		});
	}
	clear() {
		return __awaiter$6(this, void 0, void 0, function* () {
			return this.emptyBuffer().write({ overwrite: !0 });
		});
	}
	stringify() {
		return this._buffer;
	}
	isEmptyBuffer() {
		return this._buffer.length === 0;
	}
	emptyBuffer() {
		return this._buffer = "", this;
	}
	addRaw(text, addEOL = !1) {
		return this._buffer += text, addEOL ? this.addEOL() : this;
	}
	addEOL() {
		return this.addRaw(os.EOL);
	}
	addCodeBlock(code, lang) {
		let attrs = Object.assign({}, lang && { lang }), element = this.wrap("pre", this.wrap("code", code), attrs);
		return this.addRaw(element).addEOL();
	}
	addList(items, ordered = !1) {
		let tag = ordered ? "ol" : "ul", listItems = items.map((item) => this.wrap("li", item)).join(""), element = this.wrap(tag, listItems);
		return this.addRaw(element).addEOL();
	}
	addTable(rows) {
		let tableBody = rows.map((row) => {
			let cells = row.map((cell) => {
				if (typeof cell == "string") return this.wrap("td", cell);
				let { header, data, colspan, rowspan } = cell, tag = header ? "th" : "td", attrs = Object.assign(Object.assign({}, colspan && { colspan }), rowspan && { rowspan });
				return this.wrap(tag, data, attrs);
			}).join("");
			return this.wrap("tr", cells);
		}).join(""), element = this.wrap("table", tableBody);
		return this.addRaw(element).addEOL();
	}
	addDetails(label, content) {
		let element = this.wrap("details", this.wrap("summary", label) + content);
		return this.addRaw(element).addEOL();
	}
	addImage(src, alt, options) {
		let { width, height } = options || {}, attrs = Object.assign(Object.assign({}, width && { width }), height && { height }), element = this.wrap("img", null, Object.assign({
			src,
			alt
		}, attrs));
		return this.addRaw(element).addEOL();
	}
	addHeading(text, level) {
		let tag = `h${level}`, allowedTag = [
			"h1",
			"h2",
			"h3",
			"h4",
			"h5",
			"h6"
		].includes(tag) ? tag : "h1", element = this.wrap(allowedTag, text);
		return this.addRaw(element).addEOL();
	}
	addSeparator() {
		let element = this.wrap("hr", null);
		return this.addRaw(element).addEOL();
	}
	addBreak() {
		let element = this.wrap("br", null);
		return this.addRaw(element).addEOL();
	}
	addQuote(text, cite) {
		let attrs = Object.assign({}, cite && { cite }), element = this.wrap("blockquote", text, attrs);
		return this.addRaw(element).addEOL();
	}
	addLink(text, href) {
		let element = this.wrap("a", text, { href });
		return this.addRaw(element).addEOL();
	}
}();
const { chmod, copyFile, lstat, mkdir, open, readdir, rename, rm, rmdir, stat, symlink, unlink } = fs.promises;
process.platform, fs.constants.O_RDONLY, process.platform, events.EventEmitter, events.EventEmitter, os.default.platform(), os.default.arch();
var ExitCode;
(function(ExitCode) {
	ExitCode[ExitCode.Success = 0] = "Success", ExitCode[ExitCode.Failure = 1] = "Failure";
})(ExitCode ||= {});
function getState(name) {
	return process.env[`STATE_${name}`] || "";
}
//#endregion
//#region src/core/lib/actions/annotation.ts
function createAnnotation(enabled) {
	return enabled ? {
		notice(message) {
			console.log(`::notice::${message}`);
		},
		warning(message) {
			console.log(`::warning::${message}`);
		},
		error(message) {
			console.log(`::error::${message}`);
		}
	} : {
		notice() {},
		warning() {},
		error() {}
	};
}
const annotate = createAnnotation(!0);
//#endregion
//#region src/core/lib/docker/args.ts
function buildComposeDownArgs({ composeFile, projectName }) {
	return [
		"compose",
		"-f",
		composeFile,
		"-p",
		projectName,
		"down"
	];
}
//#endregion
//#region src/lib/compose-file.ts
const __dirname$1 = (0, node_path.dirname)((0, node_url.fileURLToPath)(require("url").pathToFileURL(__filename).href)), DEFAULT_COMPOSE_FILE = (0, node_path.join)(__dirname$1, "../docker/compose.action.yaml");
async function readLocalImageOverride(env, log = console.log) {
	return null;
}
function resolveComposeFile(override) {
	return override?.composeFile ?? DEFAULT_COMPOSE_FILE;
}
//#endregion
//#region src/core/lib/errors.ts
var ActionError = class extends Error {
	code;
	constructor(message, code) {
		super(message), this.name = new.target.name, this.code = code;
	}
};
function errorMessage(e) {
	return e instanceof Error ? e.message : String(e);
}
function capturedStderr(e) {
	let err = e && typeof e == "object" ? e : {};
	return typeof err.stderr == "string" ? err.stderr.trim() : "";
}
function describeDockerFailure(e, { operation = "docker", env = process.env, exists = node_fs.existsSync } = {}) {
	let err = e && typeof e == "object" ? e : {}, slimNote = isLikelySlimRunner(env, exists) ? " Detected a container-based GitHub-hosted runner image (e.g. \"ubuntu-slim\"): these ship a Docker client with no daemon and are not supported for this action." : "", whatHappened;
	if (err.code === "ENOENT") whatHappened = `The "docker" command was not found on this runner's PATH while running ${operation}.`;
	else {
		let captured = capturedStderr(e);
		whatHappened = `${operation} failed${captured ? `: ${captured}` : " (see the Docker output above for the underlying error)"}.`;
	}
	return `${whatHappened}${slimNote} Buildcage requires a working Docker installation (client and daemon) on the runner, on Docker Engine 25.0 or later with Compose v2.20.2 or later. Lightweight runner images such as GitHub-hosted "ubuntu-slim" ship a Docker client but no daemon and are not supported for this action. Use "ubuntu-latest", or another runner with a full Docker install, instead. See README.md and docs/security.md for details.`;
}
function isLikelySlimRunner(_env = process.env, _exists = node_fs.existsSync) {
	return _env.ImageOS === "Linux" && _exists("/run/.containerenv");
}
//#endregion
//#region src/lib/errors.ts
var SandboxError = class extends ActionError {};
//#endregion
//#region src/lib/sandbox/pinned-commands.ts
const pinned = new Map();
function hostCommand(command) {
	return pinned.get(command) ?? command;
}
//#endregion
//#region src/lib/container.ts
const CONTAINER_NAME_PATTERN = /^buildcage-proxy-[0-9a-f]{8}$/;
function isValidContainerName(name) {
	return CONTAINER_NAME_PATTERN.test(name);
}
const CONTAINER_NAME_PREFIX_RE = RegExp("^buildcage-proxy-");
function scratchDirNameFor(containerName) {
	return containerName.replace(CONTAINER_NAME_PREFIX_RE, "sandbox-");
}
const OWNER_TOKEN_VARS = [
	"GITHUB_RUN_ID",
	"GITHUB_RUN_ATTEMPT",
	"GITHUB_JOB",
	"GITHUB_ACTION"
];
function ownerToken(env) {
	let values = OWNER_TOKEN_VARS.map((name) => env[name]);
	return values.every(Boolean) ? values.join("/") : "";
}
function isContainerNotFoundError(e) {
	let err = e && typeof e == "object" ? e : {}, text = `${err.stderr ?? ""} ${err.message ?? ""}`.toLowerCase();
	return text.includes("no such object") || text.includes("no such container");
}
const captureDockerViaExec = (args, env) => (0, node_child_process.execFileSync)(hostCommand("docker"), args, {
	encoding: "utf8",
	env,
	stdio: [
		"ignore",
		"pipe",
		"pipe"
	]
});
function inspectFormat(containerName, format, exec) {
	try {
		return exec([
			"inspect",
			"--format",
			format,
			containerName
		], {
			...process.env,
			LC_ALL: "C"
		}).trim();
	} catch (e) {
		if (isContainerNotFoundError(e)) return null;
		throw new SandboxError(describeDockerFailure(e, { operation: "docker inspect" }), "DOCKER_UNAVAILABLE");
	}
}
function readContainerOwner(containerName, { exec = captureDockerViaExec } = {}) {
	let owner = inspectFormat(containerName, "{{index .Config.Labels \"io.buildcage.owner\"}}", exec);
	return owner === "<no value>" ? "" : owner;
}
//#endregion
//#region src/core/lib/docker/compose-project-name.ts
function deriveProjectName(containerName) {
	return `buildcage-${(0, node_crypto.createHash)("sha256").update(containerName).digest("hex").slice(0, 12)}`;
}
//#endregion
//#region src/lib/post-state.ts
function resolvePostState(state) {
	let problems = [], { containerName, ephemeralRoots } = state;
	if (!containerName) return {
		targets: null,
		problems
	};
	if (!isValidContainerName(containerName)) return problems.push(`container_name in GITHUB_STATE is ${JSON.stringify(containerName)}, which is not a name this action generates. Skipping all post-step cleanup: the sandboxed command can append to GITHUB_STATE, so this value cannot be trusted to name a path to unmount or delete. A proxy container and a scratch directory under /var/tmp may need manual removal.`), {
		targets: null,
		problems
	};
	let targets = {
		containerName,
		projectName: deriveProjectName(containerName)
	}, roots = parseEphemeralRoots(ephemeralRoots);
	return roots ? targets.ephemeralRoots = roots : ephemeralRoots && problems.push("ephemeral_overlay_roots in GITHUB_STATE is malformed; not logging discarded paths."), {
		targets,
		problems
	};
}
function parseEphemeralRoots(raw) {
	if (!raw) return;
	let parsed;
	try {
		parsed = JSON.parse(raw);
	} catch {
		return;
	}
	if (Array.isArray(parsed)) return parsed.every((p) => typeof p == "string" && (0, node_path.isAbsolute)(p) && !/[\x00-\x1f\x7f]/.test(p)) ? parsed : void 0;
}
//#endregion
//#region src/lib/retry-briefly.ts
function retryBriefly(fn, options = {}) {
	let { attempts = 5, delayMs = 200, retryOn = () => !0 } = options;
	for (let attempt = 1;; attempt++) try {
		return fn();
	} catch (e) {
		if (attempt >= attempts || !retryOn(e)) throw e;
		Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delayMs);
	}
}
//#endregion
//#region src/lib/sandbox/mountinfo.ts
function parseMountinfo(mountinfoContent) {
	return mountinfoContent.split("\n").filter(Boolean).map((line) => {
		let fields = line.split(" "), dashIndex = fields.indexOf("-");
		return {
			mountPoint: unescapeField(fields[4]),
			fsType: unescapeField(fields[dashIndex + 1])
		};
	});
}
function unescapeField(field) {
	return (field ?? "").replace(/\\([0-7]{3})/g, (_, octal) => String.fromCharCode(parseInt(octal, 8)));
}
//#endregion
//#region src/lib/sandbox/scratch-dir.ts
const SANDBOX_SCRATCH_BASE = `/var/tmp/buildcage-${process.getuid()}`;
function parseMountsUnder(mountinfoContent, dir) {
	let prefix = dir.endsWith("/") ? dir : `${dir}/`;
	return parseMountinfo(mountinfoContent).map(({ mountPoint }) => mountPoint).filter((mountPoint) => mountPoint === dir || mountPoint.startsWith(prefix)).sort((a, b) => b.length - a.length);
}
function defaultReadMountinfo() {
	return (0, node_fs.readFileSync)("/proc/self/mountinfo", "utf8");
}
function defaultExec(command, args) {
	(0, node_child_process.execFileSync)(hostCommand(command), args, { stdio: [
		"ignore",
		"ignore",
		"pipe"
	] });
}
function defaultRemove(path) {
	(0, node_fs.rmSync)(path, {
		recursive: !0,
		force: !0
	});
}
function unmountAllUnder(dir, deps, warn) {
	let { readMountinfo = defaultReadMountinfo, exec = defaultExec } = deps, mountPoints;
	try {
		mountPoints = parseMountsUnder(readMountinfo(), dir);
	} catch {
		return;
	}
	for (let mountPoint of mountPoints) try {
		exec("sudo", [
			"umount",
			"-R",
			"-l",
			mountPoint
		]);
	} catch (e) {
		warn?.(`Failed to unmount ${mountPoint} before cleanup: ${errorMessage(e)}`);
	}
}
function removeScratchDir(dir, deps) {
	let { exec = defaultExec, lstat = node_fs.lstatSync, remove = defaultRemove } = deps;
	retryBriefly(() => {
		try {
			remove(dir);
		} catch (e) {
			if (e.code !== "EACCES") throw e;
			let st = lstat(dir);
			if (!st.isDirectory() || st.uid !== process.getuid()) throw new SandboxError(`Refusing to sudo rm -rf ${dir}: not a directory owned by uid ${process.getuid()}.`, "SCRATCH_DIR_UNSAFE");
			exec("sudo", [
				"-n",
				"rm",
				"-rf",
				dir
			]);
		}
	}, { retryOn: (e) => e.code === "EBUSY" });
}
function cleanupScratchDir(dir, { ephemeralRoots, warn } = {}, deps = {}) {
	assertUnderScratchBase(dir), ephemeralRoots && ephemeralRoots.length > 0 && console.log(`Discarded ephemeral writes under ${ephemeralRoots.join(", ")}`), unmountAllUnder(dir, deps, warn), removeScratchDir(dir, deps);
}
function assertUnderScratchBase(dir) {
	let abs = (0, node_path.resolve)(dir);
	if ((0, node_path.dirname)(abs) !== SANDBOX_SCRATCH_BASE || !/^sandbox-[A-Za-z0-9]+$/.test((0, node_path.basename)(abs))) throw new SandboxError(`Refusing to clean up ${JSON.stringify(dir)}: not a scratch dir under ${SANDBOX_SCRATCH_BASE}.`, "SCRATCH_DIR_OUT_OF_BASE");
}
function scratchDirFor(containerName) {
	if (!isValidContainerName(containerName)) throw new SandboxError(`Refusing to derive a scratch dir from container name ${JSON.stringify(containerName)}.`, "CONTAINER_NAME_INVALID");
	return (0, node_path.join)(SANDBOX_SCRATCH_BASE, scratchDirNameFor(containerName));
}
//#endregion
//#region src/lib/post-cleanup.ts
function startedByThisStep(containerName, env, readOwner) {
	let owner = readOwner(containerName);
	return owner === null || owner === ownerToken(env);
}
function planPostCleanup(state, env, annotation, { readOwner = readContainerOwner, fileExists = node_fs.existsSync, removeScratchDir = cleanupScratchDir } = {}) {
	let { targets, problems } = resolvePostState(state);
	for (let problem of problems) annotation.error(`run post-cleanup: ${problem}`);
	if (!targets) return null;
	if (!startedByThisStep(targets.containerName, env, readOwner)) return annotation.error("run post-cleanup: the proxy container named in GITHUB_STATE was started by a different step. Skipping all post-step cleanup: tearing it down would stop that step's proxy and delete its sandbox scratch directory."), null;
	try {
		let scratchDir = scratchDirFor(targets.containerName);
		fileExists(scratchDir) && removeScratchDir(scratchDir, {
			ephemeralRoots: targets.ephemeralRoots,
			warn: annotation.warning
		});
	} catch (e) {
		annotation.warning(`run post-cleanup: failed to remove sandbox scratch dir: ${errorMessage(e)}`);
	}
	return targets;
}
//#endregion
//#region src/post.ts
async function stopProxyContainer({ containerName, projectName }) {
	let composeFile = resolveComposeFile(await readLocalImageOverride(process.env));
	(0, node_child_process.execFileSync)("docker", buildComposeDownArgs({
		composeFile,
		projectName
	}), {
		stdio: "inherit",
		env: {
			...process.env,
			PROXY_CONTAINER_NAME: containerName
		}
	});
}
function main() {
	let targets = planPostCleanup({
		containerName: getState("container_name"),
		ephemeralRoots: getState("ephemeral_overlay_roots")
	}, process.env, annotate);
	targets && stopProxyContainer(targets);
}
process.argv[1] === (0, node_url.fileURLToPath)(require("url").pathToFileURL(__filename).href) && main();
//#endregion
