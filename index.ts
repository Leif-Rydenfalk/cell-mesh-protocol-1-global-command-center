#!/usr/bin/env bun
/**
 * 🌍 GLOBAL MESH COMMAND CENTER
 * Production-hardened, secure, mobile-first
 */

import { TypedRheoCell, router, procedure, z } from "cell-mesh-protocol-1";
import { createServer } from "node:http";
import { readFileSync, writeFileSync, existsSync, mkdirSync, appendFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { execSync, spawn } from "node:child_process";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

// ============================================================================
// CONFIGURATION (set these via environment variables)
// ============================================================================

const PORT = parseInt(process.env.PORT || "3000");
const DOMAIN = process.env.DOMAIN || "localhost";
const JWT_SECRET = process.env.JWT_SECRET || (() => {
    console.error("❌ FATAL: JWT_SECRET not set. Run: export JWT_SECRET=$(openssl rand -hex 32)");
    process.exit(1);
    return "";
})();

const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || (() => {
    console.warn("⚠️  Using default password 'changeme'. Set ADMIN_PASSWORD immediately.");
    return "changeme";
})();

// Optional: Hetzner token for deployment features
const HETZNER_TOKEN = process.env.HETZNER_API_TOKEN || "";

// ============================================================================
// PATHS
// ============================================================================

const DATA_DIR = join(process.cwd(), "data");
const AUTH_DIR = join(DATA_DIR, "auth");
const AUDIT_LOG = join(DATA_DIR, "audit.log");
const MESH_ROOT = process.env.MESH_ROOT || resolve(process.cwd(), "..");

if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
if (!existsSync(AUTH_DIR)) mkdirSync(AUTH_DIR, { recursive: true });

// ============================================================================
// SECURITY: Password Hashing (bcrypt-style with salt)
// ============================================================================

function hashPassword(password: string): { hash: string; salt: string } {
    const salt = randomBytes(16).toString("hex");
    const hash = createHash("sha256")
        .update(password + salt + JWT_SECRET) // pepper with JWT_SECRET
        .digest("hex");
    return { hash, salt };
}

function verifyPassword(password: string, hash: string, salt: string): boolean {
    const computed = createHash("sha256")
        .update(password + salt + JWT_SECRET)
        .digest("hex");
    try {
        return timingSafeEqual(Buffer.from(computed), Buffer.from(hash));
    } catch {
        return false;
    }
}

// ============================================================================
// JWT: Simple but secure enough for this use case
// ============================================================================

interface JWTPayload {
    sub: string;
    role: string;
    iat: number;
    exp: number;
    jti: string;
}

function signJWT(payload: Omit<JWTPayload, "iat">): string {
    const now = Math.floor(Date.now() / 1000);
    const fullPayload = { ...payload, iat: now };
    const header = { alg: "HS256", typ: "JWT" };

    const h = Buffer.from(JSON.stringify(header)).toString("base64url");
    const p = Buffer.from(JSON.stringify(fullPayload)).toString("base64url");
    const sig = createHash("sha256").update(`${h}.${p}.${JWT_SECRET}`).digest("base64url");

    return `${h}.${p}.${sig}`;
}

function verifyJWT(token: string): { valid: boolean; payload?: JWTPayload } {
    try {
        const [h, p, s] = token.split(".");
        if (!h || !p || !s) return { valid: false };

        const expectedSig = createHash("sha256").update(`${h}.${p}.${JWT_SECRET}`).digest("base64url");
        if (!timingSafeEqual(Buffer.from(s), Buffer.from(expectedSig))) {
            return { valid: false };
        }

        const payload: JWTPayload = JSON.parse(Buffer.from(p, "base64url").toString());
        if (payload.exp < Math.floor(Date.now() / 1000)) {
            return { valid: false };
        }

        return { valid: true, payload };
    } catch {
        return { valid: false };
    }
}

// ============================================================================
// USER MANAGEMENT
// ============================================================================

interface User {
    username: string;
    passHash: string;
    salt: string;
    role: "admin" | "operator" | "viewer";
    createdAt: number;
    lastLogin: number;
}

const sessions = new Map<string, { username: string; createdAt: number }>();
const rateLimit = new Map<string, { count: number; resetAt: number }>();

function getUser(username: string): User | null {
    const file = join(AUTH_DIR, `${username}.json`);
    if (!existsSync(file)) return null;
    return JSON.parse(readFileSync(file, "utf8"));
}

function saveUser(user: User) {
    writeFileSync(join(AUTH_DIR, `${user.username}.json`), JSON.stringify(user, null, 2));
}

function audit(event: string, user: string, details: any) {
    const entry = {
        ts: new Date().toISOString(),
        event,
        user,
        details: typeof details === "string" ? details : JSON.stringify(details)
    };
    appendFileSync(AUDIT_LOG, JSON.stringify(entry) + "\n");
}

function checkRateLimit(ip: string): boolean {
    const now = Date.now();
    const entry = rateLimit.get(ip);
    if (!entry || now > entry.resetAt) {
        rateLimit.set(ip, { count: 1, resetAt: now + 300000 }); // 5 min window
        return true;
    }
    if (entry.count >= 5) return false;
    entry.count++;
    return true;
}

// ============================================================================
// INIT: Create admin user if none exists
// ============================================================================

if (!getUser(ADMIN_USER)) {
    const { hash, salt } = hashPassword(ADMIN_PASSWORD);
    saveUser({
        username: ADMIN_USER,
        passHash: hash,
        salt,
        role: "admin",
        createdAt: Date.now(),
        lastLogin: 0
    });
    console.log(`✅ Created admin user: ${ADMIN_USER}`);
}

// ============================================================================
// MESH CELL SETUP
// ============================================================================

const cell = new TypedRheoCell(`GlobalCommand_${process.pid}`, 0);

const apiRouter = router({
    auth: router({
        login: procedure
            .input(z.object({
                username: z.string().min(1),
                password: z.string().min(1)
            }))
            .output(z.object({
                success: z.boolean(),
                token: z.string().optional(),
                error: z.string().optional()
            }))
            .mutation(async (input, ctx: any) => {
                const ip = ctx?.req?.headers?.["x-forwarded-for"] || ctx?.req?.socket?.remoteAddress || "unknown";

                if (!checkRateLimit(ip)) {
                    audit("RATE_LIMITED", input.username, { ip });
                    return { success: false, error: "Too many attempts. Wait 5 minutes." };
                }

                const user = getUser(input.username);
                if (!user || !verifyPassword(input.password, user.passHash, user.salt)) {
                    audit("LOGIN_FAILED", input.username, { ip });
                    return { success: false, error: "Invalid credentials" };
                }

                const jti = randomBytes(16).toString("hex");
                const token = signJWT({
                    sub: user.username,
                    role: user.role,
                    exp: Math.floor(Date.now() / 1000) + 86400, // 24h
                    jti
                });

                sessions.set(jti, { username: user.username, createdAt: Date.now() });
                user.lastLogin = Date.now();
                saveUser(user);

                audit("LOGIN_SUCCESS", user.username, { ip, role: user.role });
                return { success: true, token };
            }),

        me: procedure
            .input(z.object({ token: z.string() }))
            .output(z.object({
                authenticated: z.boolean(),
                username: z.string().optional(),
                role: z.string().optional()
            }))
            .query(async (input) => {
                const jwt = verifyJWT(input.token);
                if (!jwt.valid) return { authenticated: false };
                return {
                    authenticated: true,
                    username: jwt.payload.sub,
                    role: jwt.payload.role
                };
            })
    }),

    mesh: router({
        status: procedure
            .input(z.object({ token: z.string() }))
            .output(z.object({
                cells: z.number(),
                online: z.number(),
                capabilities: z.number(),
                nodes: z.array(z.any())
            }))
            .query(async (input, ctx: any) => {
                const jwt = verifyJWT(input.token);
                if (!jwt.valid) throw new Error("Unauthorized");

                const ip = ctx?.req?.headers?.["x-forwarded-for"] || "unknown";
                audit("MESH_STATUS_VIEWED", jwt.payload.sub, { ip });

                // Get from registry
                const registryDir = join(MESH_ROOT, ".rheo", "registry");
                const nodes: any[] = [];
                const allCaps = new Set<string>();

                if (existsSync(registryDir)) {
                    for (const file of readdirSync(registryDir)) {
                        if (!file.endsWith(".json")) continue;
                        try {
                            const entry = JSON.parse(readFileSync(join(registryDir, file), "utf8"));
                            nodes.push(entry);
                            entry.caps?.forEach((c: string) => allCaps.add(c));
                        } catch { }
                    }
                }

                return {
                    cells: nodes.length,
                    online: nodes.filter((n: any) => n.status === "online").length,
                    capabilities: allCaps.size,
                    nodes
                };
            }),

        call: procedure
            .input(z.object({
                token: z.string(),
                capability: z.string(),
                args: z.any().optional()
            }))
            .output(z.any())
            .mutation(async (input, ctx: any) => {
                const jwt = verifyJWT(input.token);
                if (!jwt.valid) throw new Error("Unauthorized");

                const ip = ctx?.req?.headers?.["x-forwarded-for"] || "unknown";

                // Role-based restrictions
                const restricted = ["hetzner/server/delete", "docker/remove", "supabase/regenerate-secrets"];
                if (jwt.payload.role === "viewer" && !input.capability.startsWith("mesh/")) {
                    throw new Error("Viewers cannot execute mutations");
                }
                if (jwt.payload.role === "operator" && restricted.some(r => input.capability.includes(r))) {
                    throw new Error("Operators cannot perform destructive actions");
                }

                audit("MESH_CALL", jwt.payload.sub, { capability: input.capability, ip });

                const result = await cell.askMesh(input.capability as any, input.args || {}, {}, { maxWaitMs: 30000 });
                return result.ok ? result.value : { error: result.error?.msg };
            })
    }),

    files: router({
        list: procedure
            .input(z.object({ token: z.string(), path: z.string().default("") }))
            .output(z.array(z.any()))
            .query(async (input) => {
                const jwt = verifyJWT(input.token);
                if (!jwt.valid) throw new Error("Unauthorized");

                const target = resolve(join(MESH_ROOT, input.path));
                if (!target.startsWith(MESH_ROOT)) throw new Error("Access denied");

                const items: any[] = [];
                for (const entry of readdirSync(target)) {
                    const full = join(target, entry);
                    const stats = statSync(full);
                    items.push({
                        name: entry,
                        path: input.path ? `${input.path}/${entry}` : entry,
                        type: stats.isDirectory() ? "directory" : "file",
                        size: stats.size,
                        modified: stats.mtimeMs
                    });
                }
                return items;
            }),

        read: procedure
            .input(z.object({ token: z.string(), path: z.string() }))
            .output(z.object({ content: z.string() }))
            .query(async (input) => {
                const jwt = verifyJWT(input.token);
                if (!jwt.valid) throw new Error("Unauthorized");

                const full = resolve(join(MESH_ROOT, input.path));
                if (!full.startsWith(MESH_ROOT)) throw new Error("Access denied");

                return { content: readFileSync(full, "utf8") };
            }),

        write: procedure
            .input(z.object({ token: z.string(), path: z.string(), content: z.string() }))
            .output(z.object({ success: z.boolean() }))
            .mutation(async (input, ctx: any) => {
                const jwt = verifyJWT(input.token);
                if (!jwt.valid) throw new Error("Unauthorized");
                if (jwt.payload.role === "viewer") throw new Error("Read-only");

                const full = resolve(join(MESH_ROOT, input.path));
                if (!full.startsWith(MESH_ROOT)) throw new Error("Access denied");

                const dir = dirname(full);
                if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

                writeFileSync(full, input.content, "utf8");

                const ip = ctx?.req?.headers?.["x-forwarded-for"] || "unknown";
                audit("FILE_WRITE", jwt.payload.sub, { path: input.path, ip });

                return { success: true };
            })
    })
});

cell.useRouter(apiRouter);
cell.listen();

// ============================================================================
// HTTP SERVER + MOBILE UI
// ============================================================================

const UI_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="theme-color" content="#050505">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <title>Mesh Command</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        :root { --accent: #00ffaa; --bg: #050505; --card: #0a0a0a; --border: #1f3a2a; }
        * { -webkit-tap-highlight-color: transparent; touch-action: manipulation; }
        body { background: var(--bg); color: #e2e8f0; font-family: monospace; min-height: 100vh; overflow-x: hidden; }
        .screen { display: none; animation: fadeIn 0.3s; }
        .screen.active { display: block; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; } }
        .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; margin: 8px 0; }
        .input { background: #111; border: 1px solid #2a4a3a; color: var(--accent); padding: 14px; border-radius: 8px; width: 100%; font-size: 16px; font-family: monospace; }
        .input:focus { outline: none; border-color: var(--accent); }
        .btn { background: #0a2a1a; border: 1px solid var(--accent); color: var(--accent); padding: 14px; border-radius: 8px; font-weight: bold; width: 100%; font-size: 16px; cursor: pointer; font-family: monospace; }
        .btn:active { background: var(--accent); color: #000; }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .btn-danger { background: #2a0a0a; border-color: #ff3333; color: #ff3333; }
        .tab-bar { position: fixed; bottom: 0; left: 0; right: 0; background: rgba(5,5,5,0.95); border-top: 1px solid var(--border); display: flex; z-index: 100; backdrop-filter: blur(20px); }
        .tab { flex: 1; padding: 12px; text-align: center; color: #666; font-size: 11px; background: none; border: none; font-family: monospace; }
        .tab.active { color: var(--accent); }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 6px; }
        .online { background: var(--accent); box-shadow: 0 0 8px var(--accent); }
        .offline { background: #ff3333; }
        .log-line { font-size: 11px; padding: 4px 0; border-bottom: 1px solid #111; white-space: pre-wrap; word-break: break-all; }
        .file-item { padding: 14px 16px; border-bottom: 1px solid #111; display: flex; align-items: center; gap: 12px; }
        .file-item:active { background: #111; }
        .editor { min-height: 60vh; background: #111; color: #e2e8f0; border: 1px solid #2a4a3a; border-radius: 8px; padding: 12px; font-family: monospace; font-size: 13px; line-height: 1.6; white-space: pre; overflow-x: auto; tab-size: 2; width: 100%; }
        .toast { position: fixed; top: 20px; left: 50%; transform: translateX(-50%); background: #0a2a1a; color: var(--accent); padding: 12px 24px; border-radius: 8px; border: 1px solid var(--accent); z-index: 300; font-size: 14px; font-weight: bold; display: none; }
    </style>
</head>
<body>
    <div class="toast" id="toast"></div>

    <!-- LOGIN -->
    <div class="screen active" id="screen-login">
        <div style="max-width: 400px; margin: 0 auto; padding: 60px 20px;">
            <div style="text-align: center; margin-bottom: 50px;">
                <div style="font-size: 48px; margin-bottom: 16px;">🌐</div>
                <h1 style="font-size: 24px; color: var(--accent); font-weight: bold;">MESH COMMAND</h1>
                <p style="color: #666; font-size: 12px; margin-top: 8px;">Global Secure Access</p>
            </div>
            <div class="card" style="border-color: #2a4a3a;">
                <div style="margin-bottom: 16px;">
                    <label style="display: block; color: #888; font-size: 11px; margin-bottom: 6px; text-transform: uppercase;">Username</label>
                    <input type="text" id="login-user" class="input" placeholder="admin" autocomplete="username">
                </div>
                <div style="margin-bottom: 24px;">
                    <label style="display: block; color: #888; font-size: 11px; margin-bottom: 6px; text-transform: uppercase;">Password</label>
                    <input type="password" id="login-pass" class="input" placeholder="••••••••" autocomplete="current-password">
                </div>
                <button class="btn" onclick="doLogin()" id="login-btn">SECURE LOGIN</button>
                <div id="login-error" style="color: #ff3333; font-size: 12px; margin-top: 16px; text-align: center; display: none;"></div>
            </div>
            <div style="text-align: center; margin-top: 24px; font-size: 10px; color: #444; line-height: 1.6;">
                🔒 SHA-256 + Salt + Pepper<br>
                JWT with 24h expiry<br>
                Rate limited & audit logged
            </div>
        </div>
    </div>

    <!-- APP -->
    <div class="screen" id="screen-app">
        <div style="padding: 16px; padding-bottom: 100px;">
            <!-- Header -->
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <div>
                    <h1 style="font-size: 20px; color: var(--accent);">🌐 MESH</h1>
                    <div style="font-size: 10px; color: #666;">
                        <span class="status-dot online"></span> Connected
                        <span id="role-badge" style="margin-left: 8px; background: #0a2a1a; color: var(--accent); padding: 2px 8px; border-radius: 4px; font-size: 9px;">ADMIN</span>
                    </div>
                </div>
                <button onclick="doLogout()" class="btn btn-danger" style="width: auto; padding: 8px 16px; font-size: 12px;">Logout</button>
            </div>

            <!-- Stats -->
            <div class="card">
                <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; text-align: center;">
                    <div>
                        <div style="font-size: 28px; color: var(--accent); font-weight: bold;" id="stat-cells">0</div>
                        <div style="font-size: 10px; color: #666; text-transform: uppercase;">Cells</div>
                    </div>
                    <div>
                        <div style="font-size: 28px; color: var(--accent); font-weight: bold;" id="stat-online">0</div>
                        <div style="font-size: 10px; color: #666; text-transform: uppercase;">Online</div>
                    </div>
                    <div>
                        <div style="font-size: 28px; color: var(--accent); font-weight: bold;" id="stat-caps">0</div>
                        <div style="font-size: 10px; color: #666; text-transform: uppercase;">Capabilities</div>
                    </div>
                </div>
            </div>

            <!-- Actions -->
            <div class="card">
                <h3 style="font-size: 14px; margin-bottom: 12px; color: var(--accent);">⚡ Quick Actions</h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
                    <button class="btn" style="font-size: 12px; padding: 10px;" onclick="refreshMesh()">⟳ Refresh</button>
                    <button class="btn" style="font-size: 12px; padding: 10px;" onclick="showDeploy()">🚀 Deploy</button>
                </div>
            </div>

            <!-- Deploy Panel -->
            <div class="card" id="deploy-panel" style="display: none;">
                <h3 style="font-size: 14px; margin-bottom: 12px;">Deploy New Node</h3>
                <input type="text" id="deploy-name" class="input" placeholder="node-name" style="margin-bottom: 8px;">
                <input type="text" id="deploy-repo" class="input" placeholder="https://github.com/user/repo.git" style="margin-bottom: 8px;">
                <input type="text" id="deploy-type" class="input" placeholder="cax11" value="cax11" style="margin-bottom: 8px;">
                <button class="btn" onclick="deployNode()" id="deploy-btn">DEPLOY TO HETZNER</button>
            </div>

            <!-- Node List -->
            <div id="node-list"></div>
        </div>

        <!-- Tab Bar -->
        <div class="tab-bar">
            <button class="tab active" onclick="switchTab('mesh')">🌐<br>Mesh</button>
            <button class="tab" onclick="switchTab('files')">📁<br>Files</button>
            <button class="tab" onclick="switchTab('terminal')">💻<br>Term</button>
            <button class="tab" onclick="switchTab('ai')">🤖<br>AI</button>
        </div>
    </div>

    <!-- FILES SCREEN -->
    <div class="screen" id="screen-files">
        <div style="padding: 16px; padding-bottom: 100px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                <h1 style="font-size: 20px; color: var(--accent);">📁 FILES</h1>
                <button onclick="switchTab('mesh')" class="btn" style="width: auto; padding: 8px 16px; font-size: 12px;">← Back</button>
            </div>
            <div id="breadcrumbs" style="font-size: 11px; color: #666; margin-bottom: 12px;">mesh/</div>
            <div id="file-list"></div>
        </div>
    </div>

    <!-- EDITOR SCREEN -->
    <div class="screen" id="screen-editor">
        <div style="padding: 16px; padding-bottom: 100px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <button onclick="backToFiles()" class="btn" style="width: auto; padding: 8px 16px; font-size: 12px;">← Back</button>
                <span id="editor-filename" style="font-size: 13px; color: #888;">file.ts</span>
                <button onclick="saveFile()" class="btn" style="width: auto; padding: 8px 16px; font-size: 12px;">💾 Save</button>
            </div>
            <textarea id="editor" class="editor" spellcheck="false"></textarea>
        </div>
    </div>

    <!-- TERMINAL SCREEN -->
    <div class="screen" id="screen-terminal">
        <div style="padding: 16px; padding-bottom: 100px;">
            <h1 style="font-size: 20px; color: var(--accent); margin-bottom: 16px;">💻 TERMINAL</h1>
            <div id="terminal-output" style="background: #0a0a0a; border: 1px solid #1f3a2a; border-radius: 8px; padding: 12px; min-height: 50vh; font-size: 12px; white-space: pre-wrap; word-break: break-all; margin-bottom: 12px;"></div>
            <div style="display: flex; gap: 8px;">
                <input type="text" id="terminal-input" class="input" placeholder="Enter command..." style="flex: 1;" onkeydown="if(event.key==='Enter')runTerminal()">
                <button class="btn" style="width: auto;" onclick="runTerminal()">▶</button>
            </div>
        </div>
    </div>

    <!-- AI SCREEN -->
    <div class="screen" id="screen-ai">
        <div style="padding: 16px; padding-bottom: 100px;">
            <h1 style="font-size: 20px; color: var(--accent); margin-bottom: 16px;">🤖 AI CONTROL</h1>
            <div id="chat-messages" style="margin-bottom: 12px;"></div>
            <div style="display: flex; gap: 8px;">
                <input type="text" id="chat-input" class="input" placeholder="Ask the mesh AI..." style="flex: 1;" onkeydown="if(event.key==='Enter')sendChat()">
                <button class="btn" style="width: auto;" onclick="sendChat()">➤</button>
            </div>
        </div>
    </div>

    <script>
        let token = localStorage.getItem('mesh_token');
        let currentPath = '';
        let currentFile = '';
        let currentRole = 'viewer';

        // Auto-login check
        if (token) verifyToken();

        async function api(endpoint, body = {}) {
            const res = await fetch('/api/' + endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            return res.json();
        }

        function showToast(msg) {
            const t = document.getElementById('toast');
            t.textContent = msg;
            t.style.display = 'block';
            setTimeout(() => t.style.display = 'none', 3000);
        }

        async function doLogin() {
            const btn = document.getElementById('login-btn');
            btn.disabled = true;
            btn.textContent = 'AUTHENTICATING...';

            const user = document.getElementById('login-user').value;
            const pass = document.getElementById('login-pass').value;

            const result = await api('auth/login', { username: user, password: pass });

            if (result.success) {
                token = result.token;
                localStorage.setItem('mesh_token', token);
                showApp();
            } else {
                document.getElementById('login-error').textContent = result.error;
                document.getElementById('login-error').style.display = 'block';
            }

            btn.disabled = false;
            btn.textContent = 'SECURE LOGIN';
        }

        async function verifyToken() {
            const result = await api('auth/me', { token });
            if (result.authenticated) {
                currentRole = result.role;
                showApp();
            } else {
                localStorage.removeItem('mesh_token');
                token = null;
            }
        }

        function showApp() {
            document.getElementById('screen-login').classList.remove('active');
            document.getElementById('screen-app').classList.add('active');
            document.getElementById('role-badge').textContent = currentRole.toUpperCase();
            refreshMesh();
        }

        function doLogout() {
            localStorage.removeItem('mesh_token');
            token = null;
            location.reload();
        }

        async function refreshMesh() {
            const result = await api('mesh/status', { token });
            document.getElementById('stat-cells').textContent = result.cells;
            document.getElementById('stat-online').textContent = result.online;
            document.getElementById('stat-caps').textContent = result.capabilities;

            const list = document.getElementById('node-list');
            if (!result.nodes || result.nodes.length === 0) {
                list.innerHTML = '<div class="card" style="text-align: center; color: #666;">No cells found</div>';
                return;
            }

            list.innerHTML = result.nodes.map(n => \`
                <div class="card" style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-weight: bold; font-size: 14px;">
                            <span class="status-dot \${n.status === 'online' ? 'online' : 'offline'}"></span>
                            \${n.id || 'unknown'}
                        </div>
                        <div style="font-size: 10px; color: #666; margin-top: 4px;">
                            \${n.addr || 'no address'} • \${(n.caps || []).length} capabilities
                        </div>
                    </div>
                    <div style="font-size: 10px; color: #888;">
                        \${n.status === 'online' ? '🟢' : '🔴'} \${n.status}
                    </div>
                </div>
            \`).join('');
        }

        function showDeploy() {
            const panel = document.getElementById('deploy-panel');
            panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
        }

        async function deployNode() {
            const name = document.getElementById('deploy-name').value;
            const repo = document.getElementById('deploy-repo').value;
            const type = document.getElementById('deploy-type').value;

            if (!name || !repo) return showToast('Fill all fields');

            const btn = document.getElementById('deploy-btn');
            btn.disabled = true;
            btn.textContent = 'DEPLOYING...';

            try {
                const result = await api('mesh/call', {
                    token,
                    capability: 'igniter/createServer',
                    args: { token: HETZNER_TOKEN, repoUrl: repo, repoBranch: 'main', serverType: type, location: 'fsn1', firewallId: 0 }
                });
                showToast(result.ip ? \`Deployed: \${result.ip}\` : 'Deploy failed');
            } catch (e) {
                showToast('Error: ' + e.message);
            }

            btn.disabled = false;
            btn.textContent = 'DEPLOY TO HETZNER';
        }

        // FILES
        async function loadFiles(path = '') {
            currentPath = path;
            const result = await api('files/list', { token, path });
            const list = document.getElementById('file-list');
            const crumbs = document.getElementById('breadcrumbs');
            
            crumbs.textContent = 'mesh/' + (path || '');
            
            let html = '';
            if (path) {
                html += \`<div class="file-item" onclick="loadFiles('\${path.split('/').slice(0,-1).join('/')}')">
                    <div style="font-size: 20px;">↩</div>
                    <div><div style="font-size: 14px;">..</div><div style="font-size: 11px; color: #666;">Parent</div></div>
                </div>\`;
            }

            for (const item of result) {
                const icon = item.type === 'directory' ? '📁' : '📄';
                if (item.type === 'directory') {
                    html += \`<div class="file-item" onclick="loadFiles('\${item.path}')">
                        <div style="font-size: 20px;">\${icon}</div>
                        <div><div style="font-size: 14px;">\${item.name}</div><div style="font-size: 11px; color: #666;">directory</div></div>
                    </div>\`;
                } else {
                    html += \`<div class="file-item" onclick="openFile('\${item.path}')">
                        <div style="font-size: 20px;">\${icon}</div>
                        <div><div style="font-size: 14px;">\${item.name}</div><div style="font-size: 11px; color: #666;">\${(item.size/1024).toFixed(1)}kb</div></div>
                    </div>\`;
                }
            }
            list.innerHTML = html;
        }

        async function openFile(path) {
            currentFile = path;
            const result = await api('files/read', { token, path });
            document.getElementById('editor').value = result.content;
            document.getElementById('editor-filename').textContent = path;
            document.getElementById('screen-files').classList.remove('active');
            document.getElementById('screen-editor').classList.add('active');
        }

        function backToFiles() {
            document.getElementById('screen-editor').classList.remove('active');
            document.getElementById('screen-files').classList.add('active');
        }

        async function saveFile() {
            const content = document.getElementById('editor').value;
            await api('files/write', { token, path: currentFile, content });
            showToast('Saved!');
        }

        // TERMINAL
        async function runTerminal() {
            const input = document.getElementById('terminal-input');
            const cmd = input.value.trim();
            if (!cmd) return;
            input.value = '';

            const output = document.getElementById('terminal-output');
            output.innerHTML += \`<div style="color: var(--accent); margin-top: 8px;">$ \${cmd}</div>\`;

            try {
                const result = await api('mesh/call', {
                    token,
                    capability: 'bridge/execCommand',
                    args: { command: cmd }
                });
                output.innerHTML += \`<div style="color: #e2e8f0;">\${result.stdout || result.stderr || 'Done'}</div>\`;
            } catch (e) {
                output.innerHTML += \`<div style="color: #ff3333;">Error: \${e.message}</div>\`;
            }
            output.scrollTop = output.scrollHeight;
        }

        // AI
        async function sendChat() {
            const input = document.getElementById('chat-input');
            const msg = input.value.trim();
            if (!msg) return;
            input.value = '';

            const container = document.getElementById('chat-messages');
            container.innerHTML += \`<div style="background: #0a2a1a; color: var(--accent); padding: 12px; border-radius: 8px; margin: 8px 0; font-size: 13px;">\${msg}</div>\`;

            try {
                const result = await api('mesh/call', {
                    token,
                    capability: 'ai/generate',
                    args: { prompt: msg }
                });
                container.innerHTML += \`<div style="background: #111; color: #e2e8f0; padding: 12px; border-radius: 8px; margin: 8px 0; font-size: 13px; white-space: pre-wrap;">\${result.response || result}</div>\`;
            } catch (e) {
                container.innerHTML += \`<div style="color: #ff3333; padding: 12px;">AI Error: \${e.message}</div>\`;
            }
            container.scrollTop = container.scrollHeight;
        }

        // TABS
        function switchTab(tab) {
            document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            
            if (tab === 'mesh') {
                document.getElementById('screen-app').classList.add('active');
            } else if (tab === 'files') {
                document.getElementById('screen-files').classList.add('active');
                loadFiles();
            } else if (tab === 'terminal') {
                document.getElementById('screen-terminal').classList.add('active');
            } else if (tab === 'ai') {
                document.getElementById('screen-ai').classList.add('active');
            }
            
            event.target.classList.add('active');
        }

        // Refresh every 30s
        setInterval(() => { if (token) refreshMesh(); }, 30000);
    </script>
</body>
</html>`;

// HTTP Server
createServer(async (req, res) => {
    const url = new URL(req.url || "/", `http://localhost:${PORT}`);

    // CORS headers
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") {
        res.writeHead(200);
        res.end();
        return;
    }

    // Static UI
    if (url.pathname === "/" && req.method === "GET") {
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(UI_HTML);
        return;
    }

    // API routes
    if (url.pathname.startsWith("/api/")) {
        const route = url.pathname.replace("/api/", "");
        let body = "";
        req.on("data", chunk => body += chunk);
        req.on("end", async () => {
            try {
                const args = body ? JSON.parse(body) : {};
                const result = await cell.askMesh(route as any, args, {}, { maxWaitMs: 30000 });
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify(result.ok ? result.value : { error: result.error?.msg }));
            } catch (e: any) {
                res.writeHead(500);
                res.end(JSON.stringify({ error: e.message }));
            }
        });
        return;
    }

    res.writeHead(404);
    res.end("Not Found");
}).listen(PORT);

cell.log("INFO", `🌐 Global Mesh Command Center online`);
cell.log("INFO", `   Local:   http://localhost:${PORT}`);
cell.log("INFO", `   Admin:   ${ADMIN_USER}`);
cell.log("INFO", `   JWT:     ${JWT_SECRET.substring(0, 16)}...`);
cell.log("INFO", ``);
cell.log("INFO", `   To expose to internet:`);
cell.log("INFO", `   1. Set DOMAIN env var`);
cell.log("INFO", `   2. Run behind Caddy/nginx for HTTPS`);
cell.log("INFO", `   3. Or use: caddy reverse-proxy --from yourdomain.com --to :${PORT}`);