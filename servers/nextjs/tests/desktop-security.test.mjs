import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import test from "node:test";
import { build } from "esbuild";

const require = createRequire(import.meta.url);
const { NextRequest } = require("next/server");
const TOKEN = "a".repeat(64);
let security, directory;
const originalFetch = globalThis.fetch;
const savedEnv = { ...process.env };

test.before(async () => {
  directory = await mkdtemp(path.join(tmpdir(), "presenton-desktop-security-"));
  const entry = path.join(directory, "entry.ts");
  const output = path.join(directory, "bundle.cjs");
  const source = (relative) => JSON.stringify(path.resolve(relative));
  await writeFile(entry, [
    `export * from ${source("lib/desktop-auth.ts")};`,
    `export * as configRoute from ${source("app/api/user-config/route.ts")};`,
    `export * as telemetryRoute from ${source("app/api/telemetry-status/route.ts")};`,
    `export * as runtimeRoute from ${source("app/api/runtime-config/route.ts")};`,
    `export { handleSaveLLMConfig } from ${source("utils/storeHelpers.ts")};`,
    `export { store } from ${source("store/store.ts")};`,
    `export * as readFileRoute from ${source("app/api/read-file/route.ts")};`,
    `export * from ${source("lib/readable-local-file.ts")};`,
    `export * from ${source("proxy.ts")};`,
    `export * as electronAuth from ${source("../../electron/app/utils/desktop-auth.ts")};`,
    `export * as electronFiles from ${source("../../electron/app/utils/readable-file-access.ts")};`,
  ].join("\n"));
  await build({ entryPoints: [entry], outfile: output, bundle: true, platform: "node", format: "cjs", tsconfig: path.resolve("tsconfig.json"), logLevel: "silent", plugins: [{
    name: "test-runtime",
    setup(builder) {
      builder.onResolve({ filter: /^next\/server$/ }, () => ({ path: require.resolve("next/server"), external: true }));
      builder.onResolve({ filter: /^\.\/constants$/ }, (args) => args.importer.endsWith("readable-file-access.ts") ? { path: "electron-paths", namespace: "test-paths" } : undefined);
      builder.onLoad({ filter: /.*/, namespace: "test-paths" }, () => ({ contents: "export const getAppDataDir = () => process.env.APP_DATA_DIRECTORY; export const getTempDir = () => process.env.TEMP_DIRECTORY;", loader: "js" }));
    },
  }] });
  process.env.CAN_CHANGE_KEYS = "false"; // Legacy deployments must no longer lock admins out.
  security = require(output);
  Object.assign(process.env, { PRESENTON_ELECTRON: "true", PRESENTON_DESKTOP_TOKEN: TOKEN, PRESENTON_DESKTOP_ORIGINS: "http://127.0.0.1:40001,http://127.0.0.1:40000", DISABLE_AUTH: "true", NEXT_PUBLIC_URL: "http://127.0.0.1:40001", NEXT_PUBLIC_FAST_API: "http://127.0.0.1:40000", FAST_API_INTERNAL_URL: "http://127.0.0.1:40000", APP_DATA_DIRECTORY: path.join(directory, "data"), TEMP_DIRECTORY: path.join(directory, "temp") });
  await mkdir(process.env.APP_DATA_DIRECTORY);
  await mkdir(process.env.TEMP_DIRECTORY);
});

test.after(async () => {
  globalThis.fetch = originalFetch;
  for (const key of Object.keys(process.env)) if (!(key in savedEnv)) delete process.env[key];
  Object.assign(process.env, savedEnv);
  await rm(directory, { recursive: true, force: true });
});

function request(pathname = "/api/user-config", options = {}) {
  return new NextRequest(`http://127.0.0.1:40001${pathname}`, { ...options, headers: { host: "127.0.0.1:40001", ...options.headers } });
}
const authorized = { "x-presenton-desktop-token": TOKEN };

test("desktop transport rejects anonymous callers across API, assets, pages and export exceptions", async () => {
  for (const url of ["/api/user-config", "/api/read-file", "/api/runtime-config", "/api/v1/auth/status", "/api/export-presentation-data/id", "/app_data/fastapi.db", "/static/icon.svg", "/pdf-maker?exportSession=arbitrary", "/dashboard", "/_next/image?url=private"]) {
    assert.equal((await security.proxy(request(url))).status, 401, url);
  }
});

test("host and origin checks still reject requests with a valid credential", () => {
  for (const headers of [{ origin: "https://attacker.example" }, { origin: "null" }, { host: "attacker.example:40001" }, { host: "127.0.0.1:40002" }, { host: "evil", "x-forwarded-host": "127.0.0.1:40001" }]) {
    assert.equal(security.desktopRequestDenied(request(undefined, { headers: { ...authorized, ...headers } })).status, 403);
  }
  assert.equal(security.desktopRequestDenied(request(undefined, { headers: { "x-presenton-desktop-token": "b".repeat(64) } })).status, 401);
  assert.equal(security.desktopRequestDenied(request(undefined, { headers: { cookie: `presenton_desktop_session=${TOKEN}` } })), null);
  const old = process.env.PRESENTON_DESKTOP_TOKEN;
  delete process.env.PRESENTON_DESKTOP_TOKEN;
  assert.equal(security.desktopRequestDenied(request(undefined, { headers: authorized })).status, 503);
  process.env.PRESENTON_DESKTOP_TOKEN = old;
});

test("settings reject the original text/plain attack and accept authorized JSON updates", async () => {
  const calls = [];
  let config = { LLM: "openai", OPENAI_API_KEY: "saved-key" };
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith("/auth/status")) return Response.json({ configured: true, authenticated: true, user_id: null, role: "admin" });
    if (options.method === "PUT") config = { ...config, ...JSON.parse(options.body) };
    return Response.json(config);
  };
  const body = JSON.stringify({ LLM: "custom", CUSTOM_MODEL: "test", CUSTOM_LLM_URL: "https://attacker.example/v1" });
  for (const type of ["text/plain", "application/json"]) {
    assert.equal((await security.configRoute.POST(request(undefined, { method: "POST", headers: { "content-type": type }, body }))).status, 401);
  }
  assert.equal(calls.length, 0);
  assert.equal((await security.configRoute.GET(request())).status, 401);
  assert.equal((await security.configRoute.POST(request(undefined, { method: "POST", headers: { ...authorized, "content-type": "text/plain" }, body }))).status, 415);
  assert.equal(config.LLM, "openai");
  const response = await security.configRoute.POST(request(undefined, { method: "POST", headers: { ...authorized, "content-type": "application/json; charset=utf-8" }, body }));
  assert.equal(response.status, 200);
  assert.equal(config.LLM, "custom");
  assert.equal(calls.at(-1).options.headers["x-presenton-desktop-token"], TOKEN);
  assert.equal((await (await security.configRoute.GET(request(undefined, { headers: authorized }))).json()).OPENAI_API_KEY, "saved-key");
});

test("frontend provider saves pass the settings route JSON check", async () => {
  let savedConfig;
  globalThis.fetch = async (url, options) => {
    if (url === "/api/user-config") {
      const browserRequest = new NextRequest("http://127.0.0.1:40001/api/user-config", options);
      browserRequest.headers.set("host", "127.0.0.1:40001");
      browserRequest.headers.set("x-presenton-desktop-token", TOKEN);
      return security.configRoute.POST(browserRequest);
    }
    if (url.endsWith("/auth/status")) {
      return Response.json({ configured: true, authenticated: true, user_id: null, role: "admin" });
    }
    if (url.endsWith("/admin/provider-settings") && options.method === "PUT") {
      savedConfig = JSON.parse(options.body);
      return Response.json(savedConfig);
    }
    throw new Error(`Unexpected request: ${url}`);
  };

  await security.handleSaveLLMConfig({
    LLM: "custom",
    CUSTOM_MODEL: "local-model",
    CUSTOM_LLM_URL: "http://local-provider:8080/v1",
    DISABLE_IMAGE_GENERATION: true,
  });

  assert.equal(savedConfig.LLM, "custom");
  assert.equal(savedConfig.CUSTOM_MODEL, "local-model");
  assert.equal(security.store.getState().userConfig.llm_config.CUSTOM_MODEL, "local-model");
});

test("regular users receive redacted settings and cannot change provider keys", async () => {
  const desktop = process.env.PRESENTON_ELECTRON;
  delete process.env.PRESENTON_ELECTRON;
  process.env.USER_CONFIG_PATH = path.join(directory, "userConfig.json");
  await writeFile(process.env.USER_CONFIG_PATH, JSON.stringify({
    LLM: "openai", OPENAI_MODEL: "test-model", OPENAI_API_KEY: "admin-only-key",
    AUTH_SECRET_KEY: "private-auth-secret", DISABLE_IMAGE_GENERATION: true,
  }));
  let writes = 0;
  globalThis.fetch = async (url, options) => {
    if (url.endsWith("/auth/status")) {
      return Response.json({ configured: true, authenticated: true, role: "user", user_id: "member" });
    }
    if (url.endsWith("/config/runtime")) {
      return Response.json({ config: { LLM: "openai", OPENAI_MODEL: "test-model", OPENAI_API_KEY: "__configured__", DISABLE_IMAGE_GENERATION: true } });
    }
    writes++;
    throw new Error(`Unexpected provider request: ${url}`);
  };
  try {
    const read = await security.configRoute.GET(request());
    assert.equal(read.status, 200);
    const config = await read.json();
    assert.equal(config.OPENAI_API_KEY, "__configured__");
    assert.equal(config.AUTH_SECRET_KEY, undefined);
    assert.equal(config.OPENAI_MODEL, "test-model");
    const update = await security.configRoute.POST(request(undefined, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ OPENAI_API_KEY: "replacement" }),
    }));
    assert.equal(update.status, 403);
    assert.equal(writes, 0);
  } finally {
    process.env.PRESENTON_ELECTRON = desktop;
    delete process.env.USER_CONFIG_PATH;
  }
});

test("document readers preserve previews but deny credentials, tasks, traversal and symlinks", async () => {
  const data = process.env.APP_DATA_DIRECTORY;
  const temp = process.env.TEMP_DIRECTORY;
  await mkdir(path.join(data, "uploads"));
  const document = path.join(temp, "document.txt");
  const uploaded = path.join(data, "uploads", "document.txt");
  await writeFile(document, "document text");
  await writeFile(uploaded, "uploaded text");
  await writeFile(path.join(data, "private.txt"), "secret");
  await writeFile(path.join(data, "userConfig.json"), '{"AUTH_SECRET_KEY":"secret"}');
  const task = path.join(temp, "export_task.json");
  await writeFile(task, `{"cookieHeader":"presenton_desktop_session=${TOKEN}"}`);
  const alias = path.join(temp, "alias.txt");
  await symlink(task, alias);
  const escape = path.join(data, "uploads", "alias.txt");
  await symlink(path.join(data, "private.txt"), escape);
  for (const reader of [security.readReadableLocalFile, security.electronFiles.readReadableLocalFile]) {
    assert.equal(reader(document), "document text");
    assert.equal(reader(uploaded), "uploaded text");
    for (const file of [path.join(data, "userConfig.json"), path.join(data, "private.txt"), task, alias, escape, path.join(data, "uploads", "..", "private.txt")]) assert.throws(() => reader(file), /Access denied/);
  }
});

test("account-mode pages keep their existing layout login flow", async () => {
  delete process.env.PRESENTON_ELECTRON;
  try { assert.equal((await security.proxy(request("/dashboard"))).status, 200); }
  finally { process.env.PRESENTON_ELECTRON = "true"; }
});

test("Electron bootstraps a fresh private credential and injects it only on exact app origins", async () => {
  let cookie, callback;
  const fakeSession = { cookies: { set: async (value) => { cookie = value; } }, webRequest: { onBeforeSendHeaders: (value) => { callback = value; } } };
  const origins = ["http://127.0.0.1:40001", "http://127.0.0.1:40000"];
  await security.electronAuth.initializeDesktopSession(fakeSession, origins);
  const first = cookie.value;
  assert.match(first, /^[a-f0-9]{64}$/);
  assert.equal(cookie.httpOnly, true);
  assert.equal(cookie.sameSite, "strict");
  for (const origin of origins) {
    let result;
    callback({ url: `${origin}/api/test`, requestHeaders: {} }, (value) => { result = value; });
    assert.equal(result.requestHeaders["x-presenton-desktop-token"], first);
  }
  for (const url of ["https://external.example", "http://127.0.0.1:40002", "http://127.0.0.1:40001.attacker.example", "http://localhost:40001"]) {
    let result;
    callback({ url, requestHeaders: { "X-Presenton-Desktop-Token": first, Cookie: `presenton_desktop_session=${first}; harmless=value` } }, (value) => { result = value; });
    assert.equal(result.requestHeaders["X-Presenton-Desktop-Token"], undefined);
    assert.equal(result.requestHeaders.Cookie.trim(), "harmless=value");
  }
  await security.electronAuth.initializeDesktopSession(fakeSession, origins);
  assert.notEqual(cookie.value, first);
  process.env.PRESENTON_DESKTOP_TOKEN = TOKEN;
});


test("unavailable configuration fails closed without enabling telemetry or reading JSON", async () => {
  globalThis.fetch = async (url) => url.endsWith("/auth/status")
    ? Response.json({ authenticated: true, role: "user" })
    : new Response("Unavailable", { status: 503 });
  const telemetry = await security.telemetryRoute.GET(request(undefined, { headers: authorized }));
  assert.deepEqual(await telemetry.json(), { telemetryEnabled: false });
  const runtime = await security.runtimeRoute.GET(request(undefined, { headers: authorized }));
  assert.equal(runtime.status, 503);
});
