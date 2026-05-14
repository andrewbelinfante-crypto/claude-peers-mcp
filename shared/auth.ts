/**
 * claude-peers shared auth
 *
 * The broker has no network exposure (it binds to 127.0.0.1 only), but any
 * other local process can still reach 127.0.0.1:7899. A shared secret token
 * gates every broker read/write so only claude-peers processes — the ones that
 * can read the token file — can register peers, list them, or send messages.
 *
 * The token lives at ~/.claude-peers-token, mode 0600, generated once on first
 * run. Override the path with CLAUDE_PEERS_TOKEN_FILE.
 */

import { readFileSync, writeFileSync, chmodSync } from "node:fs";
import { randomBytes } from "node:crypto";

const TOKEN_PATH =
  process.env.CLAUDE_PEERS_TOKEN_FILE ?? `${process.env.HOME}/.claude-peers-token`;

/** Header carrying the shared secret on every authenticated broker request. */
export const TOKEN_HEADER = "x-claude-peers-token";

/**
 * Read the shared token, generating it on first run. Race-safe: the create uses
 * an exclusive-write flag, so a process that loses the race re-reads instead of
 * clobbering a token another process is already using.
 */
export function getOrCreateToken(): string {
  try {
    const existing = readFileSync(TOKEN_PATH, "utf8").trim();
    if (existing) return existing;
  } catch {
    // file does not exist yet — fall through and create it
  }

  const token = randomBytes(32).toString("hex");
  try {
    writeFileSync(TOKEN_PATH, token, { mode: 0o600, flag: "wx" });
    chmodSync(TOKEN_PATH, 0o600);
    return token;
  } catch {
    // another process created it first — use theirs
    return readFileSync(TOKEN_PATH, "utf8").trim();
  }
}
