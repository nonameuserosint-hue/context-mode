/**
 * adapters/jetbrains-copilot — JetBrains Copilot platform adapter.
 *
 * Implements HookAdapter for JetBrains Copilot's JSON stdin/stdout hook paradigm.
 *
 * JetBrains Copilot hook specifics:
 *   - I/O: JSON on stdin, JSON on stdout (same paradigm as VS Code Copilot)
 *   - Hook names: PreToolUse, PostToolUse, PreCompact, SessionStart (PascalCase)
 *   - Additional hooks: Stop, SubagentStart, SubagentStop
 *   - Arg modification: `updatedInput` in hookSpecificOutput wrapper (NOT flat)
 *   - Blocking: `permissionDecision: "deny"` (same as VS Code Copilot)
 *   - Output modification: `additionalContext` in hookSpecificOutput,
 *     `decision: "block"` + reason
 *   - Tool input fields: tool_name, tool_input (snake_case)
 *   - Session ID: sessionId (camelCase)
 *   - Config: .github/hooks/*.json (same as VS Code Copilot)
 *   - Env detection: IDEA_INITIAL_DIRECTORY, IDEA_HOME, JETBRAINS_CLIENT_ID
 *   - Session dir: ~/.config/JetBrains/context-mode/sessions/
 *   - Rule file: .idea/copilot-instructions.md
 *   - MCP registration: Settings > Tools > GitHub Copilot > MCP (not file-based)
 */

import { createHash } from "node:crypto";
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  copyFileSync,
  accessSync,
  chmodSync,
  constants,
} from "node:fs";
import { resolve, join } from "node:path";
import { homedir } from "node:os";

import type {
  HookAdapter,
  HookParadigm,
  PlatformCapabilities,
  DiagnosticResult,
  PreToolUseEvent,
  PostToolUseEvent,
  PreCompactEvent,
  SessionStartEvent,
  PreToolUseResponse,
  PostToolUseResponse,
  PreCompactResponse,
  SessionStartResponse,
  HookRegistration,
} from "../types.js";

// ─────────────────────────────────────────────────────────
// JetBrains Copilot raw input types
// ─────────────────────────────────────────────────────────

interface JetBrainsCopilotHookInput {
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_output?: string;
  is_error?: boolean;
  /** JetBrains Copilot uses camelCase sessionId (NOT session_id). */
  sessionId?: string;
  source?: string;
}

// ─────────────────────────────────────────────────────────
// Hook constants (re-exported from hooks.ts)
// ─────────────────────────────────────────────────────────

import {
  HOOK_TYPES as JETBRAINS_HOOK_NAMES,
  HOOK_SCRIPTS as JETBRAINS_HOOK_SCRIPTS,
  buildHookCommand as buildJetBrainsHookCommand,
  type HookType as JetBrainsHookType,
} from "./hooks.js";

// ─────────────────────────────────────────────────────────
// Adapter implementation
// ─────────────────────────────────────────────────────────

export class JetBrainsCopilotAdapter implements HookAdapter {
  readonly name = "JetBrains Copilot";
  readonly paradigm: HookParadigm = "json-stdio";

  readonly capabilities: PlatformCapabilities = {
    preToolUse: true,
    postToolUse: true,
    preCompact: true,
    sessionStart: true,
    canModifyArgs: true,
    canModifyOutput: true,
    canInjectSessionContext: true,
  };

  // ── Input parsing ──────────────────────────────────────

  parsePreToolUseInput(raw: unknown): PreToolUseEvent {
    const input = raw as JetBrainsCopilotHookInput;
    return {
      toolName: input.tool_name ?? "",
      toolInput: input.tool_input ?? {},
      sessionId: this.extractSessionId(input),
      projectDir: this.getProjectDir(),
      raw,
    };
  }

  parsePostToolUseInput(raw: unknown): PostToolUseEvent {
    const input = raw as JetBrainsCopilotHookInput;
    return {
      toolName: input.tool_name ?? "",
      toolInput: input.tool_input ?? {},
      toolOutput: input.tool_output,
      isError: input.is_error,
      sessionId: this.extractSessionId(input),
      projectDir: this.getProjectDir(),
      raw,
    };
  }

  parsePreCompactInput(raw: unknown): PreCompactEvent {
    const input = raw as JetBrainsCopilotHookInput;
    return {
      sessionId: this.extractSessionId(input),
      projectDir: this.getProjectDir(),
      raw,
    };
  }

  parseSessionStartInput(raw: unknown): SessionStartEvent {
    const input = raw as JetBrainsCopilotHookInput;
    const rawSource = input.source ?? "startup";

    let source: SessionStartEvent["source"];
    switch (rawSource) {
      case "compact":
        source = "compact";
        break;
      case "resume":
        source = "resume";
        break;
      case "clear":
        source = "clear";
        break;
      default:
        source = "startup";
    }

    return {
      sessionId: this.extractSessionId(input),
      source,
      projectDir: this.getProjectDir(),
      raw,
    };
  }

  // ── Response formatting ────────────────────────────────

  formatPreToolUseResponse(response: PreToolUseResponse): unknown {
    if (response.decision === "deny") {
      return {
        permissionDecision: "deny",
        reason: response.reason ?? "Blocked by context-mode hook",
      };
    }
    if (response.decision === "modify" && response.updatedInput) {
      // JetBrains Copilot: updatedInput is wrapped in hookSpecificOutput
      return {
        hookSpecificOutput: {
          hookEventName: JETBRAINS_HOOK_NAMES.PRE_TOOL_USE,
          updatedInput: response.updatedInput,
        },
      };
    }
    if (response.decision === "context" && response.additionalContext) {
      // JetBrains Copilot: inject additionalContext via hookSpecificOutput
      return {
        hookSpecificOutput: {
          hookEventName: JETBRAINS_HOOK_NAMES.PRE_TOOL_USE,
          additionalContext: response.additionalContext,
        },
      };
    }
    if (response.decision === "ask") {
      // JetBrains Copilot: use deny to force user attention (no native "ask")
      return {
        permissionDecision: "deny",
        reason: response.reason ?? "Action requires user confirmation (security policy)",
      };
    }
    // "allow" — return undefined for passthrough
    return undefined;
  }

  formatPostToolUseResponse(response: PostToolUseResponse): unknown {
    if (response.updatedOutput) {
      // JetBrains Copilot: decision "block" + reason for output replacement
      return {
        hookSpecificOutput: {
          hookEventName: JETBRAINS_HOOK_NAMES.POST_TOOL_USE,
          decision: "block",
          reason: response.updatedOutput,
        },
      };
    }
    if (response.additionalContext) {
      return {
        hookSpecificOutput: {
          hookEventName: JETBRAINS_HOOK_NAMES.POST_TOOL_USE,
          additionalContext: response.additionalContext,
        },
      };
    }
    return undefined;
  }

  formatPreCompactResponse(response: PreCompactResponse): unknown {
    // JetBrains Copilot: stdout content on exit 0 is injected as context
    return response.context ?? "";
  }

  formatSessionStartResponse(response: SessionStartResponse): unknown {
    // JetBrains Copilot: stdout content is injected as additional context
    return response.context ?? "";
  }

  // ── Configuration ──────────────────────────────────────

  getSettingsPath(): string {
    // JetBrains Copilot reads `.github/hooks/*.json` at session start
    // (see Copilot agent's `loadEventsForWorkspace()`), so both JetBrains
    // and VS Code platforms use the same hook path.
    // MCP server registration in JetBrains is separate — managed via the IDE
    // Settings UI (`Settings > Tools > GitHub Copilot > MCP`), NOT this file.
    return resolve(".github", "hooks", "context-mode.json");
  }

  getSessionDir(): string {
    const dir = join(homedir(), ".config", "JetBrains", "context-mode", "sessions");
    mkdirSync(dir, { recursive: true });
    return dir;
  }

  getSessionDBPath(projectDir: string): string {
    const hash = createHash("sha256")
      .update(projectDir)
      .digest("hex")
      .slice(0, 16);
    return join(this.getSessionDir(), `${hash}.db`);
  }

  getSessionEventsPath(projectDir: string): string {
    const hash = createHash("sha256")
      .update(projectDir)
      .digest("hex")
      .slice(0, 16);
    return join(this.getSessionDir(), `${hash}-events.md`);
  }

  generateHookConfig(pluginRoot: string): HookRegistration {
    return {
      [JETBRAINS_HOOK_NAMES.PRE_TOOL_USE]: [
        {
          matcher: "",
          hooks: [
            {
              type: "command",
              command: buildJetBrainsHookCommand(JETBRAINS_HOOK_NAMES.PRE_TOOL_USE, pluginRoot),
            },
          ],
        },
      ],
      [JETBRAINS_HOOK_NAMES.POST_TOOL_USE]: [
        {
          matcher: "",
          hooks: [
            {
              type: "command",
              command: buildJetBrainsHookCommand(JETBRAINS_HOOK_NAMES.POST_TOOL_USE, pluginRoot),
            },
          ],
        },
      ],
      [JETBRAINS_HOOK_NAMES.PRE_COMPACT]: [
        {
          matcher: "",
          hooks: [
            {
              type: "command",
              command: buildJetBrainsHookCommand(JETBRAINS_HOOK_NAMES.PRE_COMPACT, pluginRoot),
            },
          ],
        },
      ],
      [JETBRAINS_HOOK_NAMES.SESSION_START]: [
        {
          matcher: "",
          hooks: [
            {
              type: "command",
              command: buildJetBrainsHookCommand(JETBRAINS_HOOK_NAMES.SESSION_START, pluginRoot),
            },
          ],
        },
      ],
    };
  }

  readSettings(): Record<string, unknown> | null {
    // Primary: .github/hooks/context-mode.json (shared Copilot agent hook config)
    try {
      const raw = readFileSync(this.getSettingsPath(), "utf-8");
      return JSON.parse(raw) as Record<string, unknown>;
    } catch {
      /* fall through to Claude Code fallback */
    }
    // Fallback: .claude/settings.json (for projects migrating from Claude Code)
    try {
      const raw = readFileSync(resolve(".claude", "settings.json"), "utf-8");
      return JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return null;
    }
  }

  writeSettings(settings: Record<string, unknown>): void {
    const configPath = this.getSettingsPath();
    mkdirSync(resolve(".github", "hooks"), { recursive: true });
    writeFileSync(
      configPath,
      JSON.stringify(settings, null, 2) + "\n",
      "utf-8",
    );
  }

  // ── Diagnostics (doctor) ─────────────────────────────────

  validateHooks(pluginRoot: string): DiagnosticResult[] {
    const results: DiagnosticResult[] = [];

    try {
      const raw = readFileSync(this.getSettingsPath(), "utf-8");
      const config = JSON.parse(raw) as Record<string, unknown>;
      const hooks = config.hooks as Record<string, unknown> | undefined;

      if (hooks?.[JETBRAINS_HOOK_NAMES.PRE_TOOL_USE]) {
        results.push({
          check: "PreToolUse hook",
          status: "pass",
          message: "PreToolUse hook configured in .github/hooks/context-mode.json",
        });
      } else {
        results.push({
          check: "PreToolUse hook",
          status: "fail",
          message: "PreToolUse not found in .github/hooks/context-mode.json",
          fix: "context-mode upgrade",
        });
      }

      if (hooks?.[JETBRAINS_HOOK_NAMES.SESSION_START]) {
        results.push({
          check: "SessionStart hook",
          status: "pass",
          message: "SessionStart hook configured in .github/hooks/context-mode.json",
        });
      } else {
        results.push({
          check: "SessionStart hook",
          status: "fail",
          message: "SessionStart not found in .github/hooks/context-mode.json",
          fix: "context-mode upgrade",
        });
      }
    } catch {
      results.push({
        check: "Hook configuration",
        status: "fail",
        message: "Could not read .github/hooks/context-mode.json",
        fix: "context-mode upgrade",
      });
    }

    results.push({
      check: "Hook scripts",
      status: "warn",
      message: `JetBrains hook wrappers should resolve to ${pluginRoot}/hooks/jetbrains-copilot/*.mjs`,
    });

    return results;
  }

  checkPluginRegistration(): DiagnosticResult {
    // JetBrains Copilot stores MCP server registration via the IDE Settings UI
    // (Settings > Tools > GitHub Copilot > MCP > Configure), not in a
    // project-scoped file we can inspect. The on-disk location is managed
    // internally by the plugin. We can't verify MCP registration from this
    // CLI context — surface a warn result with the verification path.
    return {
      check: "MCP registration",
      status: "warn",
      message:
        "JetBrains stores MCP config via Settings UI — not CLI-inspectable",
      fix: "Verify in IDE: Settings > Tools > GitHub Copilot > MCP > ensure a context-mode server entry exists",
    };
  }

  getInstalledVersion(): string {
    // JetBrains Copilot registers MCP servers via Settings UI (not
    // CLI-inspectable). All we can check is whether hook config has been
    // written to .github/hooks/context-mode.json by `context-mode upgrade`.
    const settings = this.readSettings();
    const hooks = settings?.hooks as Record<string, unknown> | undefined;
    if (hooks && Object.keys(hooks).length > 0) return "configured";
    return "unknown";
  }

  // ── Upgrade ────────────────────────────────────────────

  configureAllHooks(pluginRoot: string): string[] {
    const changes: string[] = [];
    const settings = this.readSettings() ?? {};
    const hooks = (settings.hooks as Record<string, unknown> | undefined) ?? {};

    const hookTypes = [
      JETBRAINS_HOOK_NAMES.PRE_TOOL_USE,
      JETBRAINS_HOOK_NAMES.POST_TOOL_USE,
      JETBRAINS_HOOK_NAMES.PRE_COMPACT,
      JETBRAINS_HOOK_NAMES.SESSION_START,
    ];

    for (const hookType of hookTypes) {
      const script = JETBRAINS_HOOK_SCRIPTS[hookType];
      if (!script) continue;

      hooks[hookType] = [
        {
          matcher: "",
          hooks: [
            {
              type: "command",
              command: buildJetBrainsHookCommand(hookType, pluginRoot),
            },
          ],
        },
      ];
      changes.push(`Configured ${hookType} hook`);
    }

    settings.hooks = hooks;
    this.writeSettings(settings);
    changes.push(`Wrote hook config to ${this.getSettingsPath()}`);

    return changes;
  }

  backupSettings(): string | null {
    const settingsPath = this.getSettingsPath();
    try {
      accessSync(settingsPath, constants.R_OK);
      const backupPath = settingsPath + ".bak";
      copyFileSync(settingsPath, backupPath);
      return backupPath;
    } catch {
      return null;
    }
  }

  setHookPermissions(pluginRoot: string): string[] {
    const set: string[] = [];
    const hooksDir = join(pluginRoot, "hooks", "jetbrains-copilot");
    for (const scriptName of Object.values(JETBRAINS_HOOK_SCRIPTS)) {
      const scriptPath = resolve(hooksDir, scriptName);
      try {
        accessSync(scriptPath, constants.R_OK);
        chmodSync(scriptPath, 0o755);
        set.push(scriptPath);
      } catch {
        /* skip missing scripts */
      }
    }
    return set;
  }

  updatePluginRegistry(_pluginRoot: string, _version: string): void {
    // JetBrains manages plugins through IDE marketplaces.
    // No manual registry update needed.
  }

  // ── Internal helpers ───────────────────────────────────

  /**
   * Extract session ID from JetBrains Copilot hook input.
   * JetBrains Copilot uses camelCase sessionId (NOT session_id).
   */
  private extractSessionId(input: JetBrainsCopilotHookInput): string {
    if (input.sessionId) return input.sessionId;
    if (process.env.JETBRAINS_CLIENT_ID) {
      return `jetbrains-${process.env.JETBRAINS_CLIENT_ID}`;
    }
    if (process.env.IDEA_HOME) return `idea-${process.pid}`;
    return `pid-${process.ppid}`;
  }

  /**
   * Get the project directory from JetBrains env vars.
   */
  private getProjectDir(): string {
    return process.env.IDEA_INITIAL_DIRECTORY || process.env.CLAUDE_PROJECT_DIR || process.cwd();
  }
}
