// Forge: a GitHub-compatible git forge in one process, Node 22 stdlib only.
// Serves git smart HTTP (v0 + v2), REST v3, GraphQL v4 and MCP from one
// in-memory store. No git binary, no outside service, no dependencies.
// main.ts (the entry <-> env lifecycle) stays as the starter ships it;
// this file is the whole server.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import * as zlib from 'node:zlib';

export const ZERO_OID = '0'.repeat(40);
const EPOCH = 1735689600; // 2025-01-01T00:00:00Z; deterministic timestamps
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const JSON_TYPE = 'application/json; charset=utf-8';

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

function sha1(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}
function sha1Hex(data: Buffer): Buffer {
  return createHash('sha1').update(data).digest();
}
function isOid(s: unknown): s is string {
  return typeof s === 'string' && /^[0-9a-f]{40}$/.test(s);
}
function b64encode(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64');
}
function b64decode(s: string): string | null {
  try {
    return Buffer.from(s, 'base64').toString('utf8');
  } catch {
    return null;
  }
}
function jsonBody(v: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(v)}\n`, 'utf8');
}
let reqCounter = 0;
function requestId(): string {
  reqCounter += 1;
  return `forge-${reqCounter}`;
}

// ---------------------------------------------------------------------------
// pkt-line framing (git wire protocol)
// ---------------------------------------------------------------------------

type PktKind = 'data' | 'flush' | 'delim' | 'end';
interface Pkt {
  kind: PktKind;
  payload: Buffer;
}

function pktLine(data: string | Buffer): Buffer {
  const payload = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  const len = payload.length + 4;
  const head = Buffer.alloc(4);
  head.write(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, payload]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

function decodePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const lenHex = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(lenHex)) break;
    const len = parseInt(lenHex, 16);
    if (len === 0) {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 1) {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 2) {
      out.push({ kind: 'end', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (off + len > buf.length) break;
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}

/** Split a receive-pack / upload-pack body into pkt-lines and the raw tail after the first flush. */
function splitPktAndTail(buf: Buffer): { packets: Pkt[]; tail: Buffer } {
  const packets: Pkt[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const lenHex = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(lenHex)) break;
    const len = parseInt(lenHex, 16);
    if (len === 0) {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      break;
    }
    if (len === 1) {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 2) {
      packets.push({ kind: 'end', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (off + len > buf.length) break;
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return { packets, tail: buf.subarray(off) };
}

// ---------------------------------------------------------------------------
// Git object model + packfiles
// ---------------------------------------------------------------------------

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObject {
  type: ObjType;
  data: Buffer;
}
const TYPE_CODES: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPES: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function objectId(type: ObjType, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1(Buffer.concat([head, data]));
}

/** Encode the pack entry header (type + size varint). */
function packEntryHeader(type: number, size: number): Buffer {
  const bytes: number[] = [];
  let b = (size & 0x0f) | (type << 4);
  size >>= 4;
  if (size > 0) b |= 0x80;
  bytes.push(b);
  while (size > 0) {
    b = size & 0x7f;
    size >>= 7;
    if (size > 0) b |= 0x80;
    bytes.push(b);
  }
  return Buffer.from(bytes);
}

/** Write a packfile (version 2, plain objects, no deltas) from a list of objects. */
function writePack(objects: GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const obj of objects) {
    parts.push(packEntryHeader(TYPE_CODES[obj.type], obj.data.length));
    parts.push(zlib.deflateSync(obj.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, sha1Hex(body)]);
}

/** Locate the end of a zlib stream starting at `start` by binary search on inflateSync. */
function inflateAt(buf: Buffer, start: number, wantSize: number): { data: Buffer; end: number } {
  let lo = start;
  let hi = buf.length;
  // First find any working end by exponential probe, then binary search.
  let probe = start + 1;
  let found = -1;
  while (probe <= buf.length) {
    try {
      const out = zlib.inflateSync(buf.subarray(start, probe));
      if (out.length === wantSize) {
        found = probe;
        break;
      }
    } catch {
      // truncated: need more bytes
    }
    if (probe >= buf.length) break;
    probe = Math.min(buf.length, start + (probe - start) * 2);
  }
  if (found < 0) throw new Error('zlib stream not found');
  hi = found;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    try {
      const out = zlib.inflateSync(buf.subarray(start, mid));
      if (out.length === wantSize) hi = mid;
      else lo = mid + 1;
    } catch {
      lo = mid + 1;
    }
  }
  const data = zlib.inflateSync(buf.subarray(start, lo));
  return { data, end: lo };
}

interface PackEntry {
  oid: string;
  type: ObjType;
  data: Buffer;
}

/** Parse a packfile. Plain objects only (the client never sends deltas); delta entries throw. */
function readPack(buf: Buffer): PackEntry[] {
  if (buf.length < 12 || buf.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('pack does not start with PACK');
  }
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = buf.readUInt32BE(8);
  const entries: PackEntry[] = [];
  let off = 12;
  for (let i = 0; i < count; i += 1) {
    // Type/size varint.
    let b = buf[off];
    off += 1;
    const typeCode = (b >> 4) & 0x07;
    let size = b & 0x0f;
    let shift = 4;
    while (b & 0x80) {
      b = buf[off];
      off += 1;
      size |= (b & 0x7f) << shift;
      shift += 7;
    }
    if (typeCode === 6) {
      // OFS_DELTA: negative offset varint.
      let ofsByte = buf[off];
      off += 1;
      let ofs = ofsByte & 0x7f;
      while (ofsByte & 0x80) {
        ofsByte = buf[off];
        off += 1;
        ofs = ((ofs + 1) << 7) | (ofsByte & 0x7f);
      }
      const { data, end } = inflateAt(buf, off, size);
      off = end;
      void ofs;
      void data;
      throw new Error('OFS_DELTA not supported in incoming packs');
    }
    if (typeCode === 7) {
      // REF_DELTA: 20-byte base oid.
      off += 20;
      const { end } = inflateAt(buf, off, size);
      off = end;
      throw new Error('REF_DELTA not supported in incoming packs');
    }
    const type = CODE_TYPES[typeCode];
    if (type === undefined) throw new Error(`unknown pack object type ${typeCode}`);
    const { data, end } = inflateAt(buf, off, size);
    off = end;
    if (data.length !== size) throw new Error('inflated size mismatch');
    entries.push({ oid: objectId(type, data), type, data });
  }
  return entries;
}

// ---------------------------------------------------------------------------
// Git object parsing (commits, trees, tags)
// ---------------------------------------------------------------------------

interface CommitInfo {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitInfo | null {
  const text = data.toString('utf8');
  const headEnd = text.indexOf('\n\n');
  if (headEnd < 0) return null;
  const head = text.slice(0, headEnd);
  const message = text.slice(headEnd + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  if (!isOid(tree)) return null;
  return { tree, parents, author, committer, message };
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const space = data.indexOf(0x20, off);
    if (space < 0) break;
    const mode = data.subarray(off, space).toString('ascii');
    const nul = data.indexOf(0x00, space + 1);
    if (nul < 0) break;
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}

function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const an = a.mode === '40000' ? `${a.name}/` : a.name;
    const bn = b.mode === '40000' ? `${b.name}/` : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

function parseTag(data: Buffer): { object: string; type: string; tag: string; message: string } | null {
  const text = data.toString('utf8');
  const headEnd = text.indexOf('\n\n');
  if (headEnd < 0) return null;
  let object = '';
  let type = '';
  let tag = '';
  for (const line of text.slice(0, headEnd).split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
  }
  if (!isOid(object)) return null;
  return { object, type, tag, message: text.slice(headEnd + 2) };
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

interface Issue {
  number: number;
  id: number; // REST numeric id
  globalId: string;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  seq: number;
  createdAt: string;
  updatedAt: string;
}
interface Comment {
  id: number;
  globalId: string;
  body: string;
  seq: number;
  createdAt: string;
}
interface PullRequest {
  number: number;
  id: number;
  globalId: string;
  title: string;
  body: string;
  state: 'open' | 'closed';
  head: string; // branch name
  base: string; // branch name
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  seq: number;
  createdAt: string;
}

class Repo {
  name: string;
  dbId: number;
  description: string;
  isPrivate: boolean;
  refs: Map<string, string> = new Map(); // ref -> oid
  objects: Map<string, GitObject> = new Map();
  issues: Map<number, Issue> = new Map();
  comments: Map<number, Comment[]> = new Map();
  labels: Map<string, { name: string; color: string }> = new Map();
  prs: Map<number, PullRequest> = new Map();
  nextNumber = 1; // shared issue + PR numbering, GitHub-style
  nextId = 1;
  seq = 0; // creation sequence for deterministic timestamps / ordering

  constructor(name: string, dbId: number, description: string, isPrivate: boolean) {
    this.name = name;
    this.dbId = dbId;
    this.description = description;
    this.isPrivate = isPrivate;
  }

  nextSeq(): number {
    this.seq += 1;
    return this.seq;
  }
  stamp(seq: number): string {
    return new Date((EPOCH + seq) * 1000).toISOString();
  }
  globalId(kind: string, n: number): string {
    return b64encode(`${kind}:${this.dbId}:${n}`);
  }
}

const repos = new Map<string, Repo>(); // key: name (owner is always the viewer)
let nextDbId = 1;
let globalSeq = 0;
function nextGlobalSeq(): number {
  globalSeq += 1;
  return globalSeq;
}
// The viewer's login, learned from the first owner-scoped request (the token
// owner is the only user; every repo belongs to them).
let viewerLogin: string | null = null;
function learnViewer(owner: string): string {
  if (viewerLogin === null) viewerLogin = owner;
  return viewerLogin;
}
function viewerName(): string {
  return viewerLogin ?? 'viewer';
}

// ---------------------------------------------------------------------------
// Tree / commit helpers over a repo's object store
// ---------------------------------------------------------------------------

function storeObject(repo: Repo, type: ObjType, data: Buffer): string {
  const oid = objectId(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}
function getObject(repo: Repo, oid: string): GitObject | undefined {
  return repo.objects.get(oid);
}
function commitOf(repo: Repo, oid: string): CommitInfo | null {
  const obj = getObject(repo, oid);
  if (obj === undefined || obj.type !== 'commit') return null;
  return parseCommit(obj.data);
}
function treeEntriesOf(repo: Repo, treeOid: string): TreeEntry[] {
  const obj = getObject(repo, treeOid);
  if (obj === undefined || obj.type !== 'tree') return [];
  return parseTree(obj.data);
}

/** Flatten a tree to path -> {oid, mode} (files only). */
function flattenTree(repo: Repo, treeOid: string, prefix = ''): Map<string, { oid: string; mode: string }> {
  const out = new Map<string, { oid: string; mode: string }>();
  const walk = (tree: string, pre: string): void => {
    for (const e of treeEntriesOf(repo, tree)) {
      if (e.mode === '40000') walk(e.oid, `${pre}${e.name}/`);
      else out.set(`${pre}${e.name}`, { oid: e.oid, mode: e.mode });
    }
  };
  walk(treeOid, prefix);
  return out;
}

/** Build nested tree objects from a flat file map; returns the root tree oid. */
function buildTreeFromFiles(repo: Repo, files: Map<string, { oid: string; mode: string }>): string {
  // Group by directory.
  const byDir = new Map<string, Map<string, { oid: string; mode: string }>>();
  const subdirs = new Map<string, Set<string>>();
  for (const [path, file] of files) {
    const slash = path.lastIndexOf('/');
    const dir = slash < 0 ? '' : path.slice(0, slash);
    const name = slash < 0 ? path : path.slice(slash + 1);
    if (!byDir.has(dir)) byDir.set(dir, new Map());
    byDir.get(dir)!.set(name, file);
    // Record every ancestor dir.
    let cur = dir;
    while (cur !== '') {
      const parent = cur.includes('/') ? cur.slice(0, cur.lastIndexOf('/')) : '';
      const base = cur.includes('/') ? cur.slice(cur.lastIndexOf('/') + 1) : cur;
      if (!subdirs.has(parent)) subdirs.set(parent, new Set());
      subdirs.get(parent)!.add(base);
      cur = parent;
    }
  }
  const buildDir = (dir: string): string => {
    const entries: TreeEntry[] = [];
    for (const [name, file] of byDir.get(dir) ?? []) {
      entries.push({ mode: file.mode, name, oid: file.oid });
    }
    for (const sub of subdirs.get(dir) ?? []) {
      entries.push({ mode: '40000', name: sub, oid: buildDir(dir === '' ? sub : `${dir}/${sub}`) });
    }
    return storeObject(repo, 'tree', buildTree(entries));
  };
  return buildDir('');
}

/** Create a commit object; returns its oid. */
function makeCommit(
  repo: Repo,
  treeOid: string,
  parents: string[],
  message: string,
): string {
  const seq = nextGlobalSeq();
  const epoch = EPOCH + seq;
  const who = `${viewerName()} <${viewerName()}@example.invalid> ${epoch} +0000`;
  const msg = message.endsWith('\n') ? message : `${message}\n`;
  let text = `tree ${treeOid}\n`;
  for (const p of parents) text += `parent ${p}\n`;
  text += `author ${who}\ncommitter ${who}\n\n${msg}`;
  return storeObject(repo, 'commit', Buffer.from(text, 'utf8'));
}

function refTip(repo: Repo, ref: string): string | null {
  return repo.refs.get(ref) ?? null;
}
function headRef(): string {
  return 'refs/heads/main';
}
function defaultBranchName(): string {
  return 'main';
}

/** All ancestors of a commit (including itself), via parent walk. */
function ancestors(repo: Repo, tip: string): Set<string> {
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length > 0) {
    const cur = stack.pop()!;
    if (seen.has(cur)) continue;
    seen.add(cur);
    const c = commitOf(repo, cur);
    if (c !== null) for (const p of c.parents) stack.push(p);
  }
  return seen;
}
function isAncestor(repo: Repo, maybeAncestor: string, tip: string): boolean {
  return ancestors(repo, tip).has(maybeAncestor);
}
/** First common ancestor of two tips (the one with the highest seq wins). */
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const ancA = ancestors(repo, a);
  let best: string | null = null;
  let bestSeq = -1;
  const stack = [b];
  const seen = new Set<string>();
  while (stack.length > 0) {
    const cur = stack.pop()!;
    if (seen.has(cur)) continue;
    seen.add(cur);
    if (ancA.has(cur)) {
      // Prefer the most recently created common ancestor: approximate by
      // walking b's history in BFS order from the tip.
      if (best === null) best = cur;
      void bestSeq;
      break;
    }
    const c = commitOf(repo, cur);
    if (c !== null) for (const p of c.parents) stack.push(p);
  }
  return best;
}

// ---------------------------------------------------------------------------
// Reachability / fetch computation
// ---------------------------------------------------------------------------

interface ReachResult {
  objects: Map<string, GitObject>; // oid -> object (commits, trees, blobs, tags)
  commits: Set<string>;
  shallow: string[];
  unshallow: string[];
}

/**
 * Compute the objects to send for wants, minus objects the client already has.
 * depth: commit generations from the wants (1 = wants only). shallowBoundaries:
 * commits the client already holds as shallow boundaries.
 */
function computeFetch(
  repo: Repo,
  wants: string[],
  haves: string[],
  shallowHeld: string[],
  depth: number | null,
  deepenRelative = false,
): ReachResult {
  // A relative deepen (real git's `deepen-relative`) adds N generations to
  // the client's current shallow depth. The current depth is one more than
  // the shortest parent-edge distance from a want to a held boundary (a
  // depth-1 clone's boundary IS its tip, distance 0).
  let effectiveDepth = depth;
  if (deepenRelative && depth !== null && shallowHeld.length > 0) {
    const targets = new Set(shallowHeld);
    const dist = new Map<string, number>();
    const queue: string[] = [];
    for (const w of wants) if (!dist.has(w)) { dist.set(w, 0); queue.push(w); }
    let best: number | null = null;
    while (queue.length > 0) {
      const cur = queue.shift()!;
      const d = dist.get(cur)!;
      if (targets.has(cur) && (best === null || d < best)) best = d;
      if (best !== null && d >= best) continue;
      const info = commitOf(repo, cur);
      if (info === null) continue;
      for (const p of info.parents) {
        if (!dist.has(p)) { dist.set(p, d + 1); queue.push(p); }
      }
    }
    if (best !== null) effectiveDepth = best + 1 + depth;
  }
  // Objects the client already holds.
  const held = new Map<string, GitObject>();
  const shallowHeldSet = new Set(shallowHeld);
  for (const have of haves) {
    if (shallowHeldSet.has(have)) {
      // A shallow boundary: the client holds just that commit + its tree/blobs.
      const c = commitOf(repo, have);
      if (c !== null) {
        const obj = getObject(repo, have);
        if (obj) held.set(have, obj);
        const treeObj = getObject(repo, c.tree);
        if (treeObj) held.set(c.tree, treeObj);
        for (const [, f] of flattenTree(repo, c.tree)) {
          const b = getObject(repo, f.oid);
          if (b) held.set(f.oid, b);
        }
      }
    } else {
      collectReachable(repo, [have], null, held);
    }
  }
  // Reachable from wants, depth-limited.
  const reachable = new Map<string, GitObject>();
  const sentCommits = new Set<string>();
  collectReachable(repo, wants, effectiveDepth, reachable, sentCommits);
  // Subtract held.
  for (const oid of [...reachable.keys()]) {
    if (held.has(oid)) reachable.delete(oid);
  }
  // Boundary commits: sent commits whose parents were not all sent.
  const shallow: string[] = [];
  for (const c of sentCommits) {
    const info = commitOf(repo, c);
    if (info !== null && info.parents.length > 0) {
      const allParentsSent = info.parents.every((p) => sentCommits.has(p));
      if (!allParentsSent) shallow.push(c);
    }
  }
  // Unshallow: previously-shallow commits whose parents are now all sent.
  const unshallow: string[] = [];
  for (const s of shallowHeld) {
    if (!sentCommits.has(s)) continue;
    const info = commitOf(repo, s);
    if (info !== null && info.parents.every((p) => sentCommits.has(p))) unshallow.push(s);
  }
  return { objects: reachable, commits: sentCommits, shallow, unshallow };
}

/** Collect the reachable closure of oids into `into`; depth limits commit generations. */
function collectReachable(
  repo: Repo,
  oids: string[],
  depth: number | null,
  into: Map<string, GitObject>,
  sentCommits?: Set<string>,
): void {
  const visitCommit = (oid: string, gen: number): void => {
    if (into.has(oid)) return;
    const obj = getObject(repo, oid);
    if (obj === undefined) return;
    into.set(oid, obj);
    if (obj.type !== 'commit') return;
    if (sentCommits) sentCommits.add(oid);
    const info = parseCommit(obj.data);
    if (info === null) return;
    visitTree(info.tree);
    if (depth === null || gen + 1 < depth) {
      for (const p of info.parents) visitCommit(p, gen + 1);
    }
  };
  const visitTree = (oid: string): void => {
    if (into.has(oid)) return;
    const obj = getObject(repo, oid);
    if (obj === undefined) return;
    into.set(oid, obj);
    if (obj.type !== 'tree') return;
    for (const e of parseTree(obj.data)) {
      if (e.mode === '40000') visitTree(e.oid);
      else {
        const child = getObject(repo, e.oid);
        if (child) into.set(e.oid, child);
      }
    }
  };
  const visitTag = (oid: string): void => {
    if (into.has(oid)) return;
    const obj = getObject(repo, oid);
    if (obj === undefined) return;
    into.set(oid, obj);
    if (obj.type !== 'tag') return;
    const tag = parseTag(obj.data);
    if (tag === null) return;
    const target = getObject(repo, tag.object);
    if (target === undefined) return;
    if (target.type === 'commit') visitCommit(tag.object, 0);
    else if (target.type === 'tree') visitTree(tag.object);
    else if (target.type === 'tag') visitTag(tag.object);
    else into.set(tag.object, target);
  };
  for (const oid of oids) {
    const obj = getObject(repo, oid);
    if (obj === undefined) continue;
    if (obj.type === 'commit') visitCommit(oid, 0);
    else if (obj.type === 'tree') visitTree(oid);
    else if (obj.type === 'tag') visitTag(oid);
    else into.set(oid, obj);
  }
}

/** Diff two flat file maps. Returns changed paths with line counts. */
interface FileChange {
  path: string;
  status: 'added' | 'modified' | 'removed';
  additions: number;
  deletions: number;
}
function countLines(buf: Buffer): number {
  if (buf.length === 0) return 0;
  const text = buf.toString('utf8');
  const lines = text.split('\n');
  // A trailing newline does not start a new line.
  return text.endsWith('\n') ? lines.length - 1 : lines.length;
}
function diffFiles(
  repo: Repo,
  oldFiles: Map<string, { oid: string; mode: string }>,
  newFiles: Map<string, { oid: string; mode: string }>,
): FileChange[] {
  const out: FileChange[] = [];
  const paths = new Set([...oldFiles.keys(), ...newFiles.keys()]);
  for (const path of [...paths].sort()) {
    const o = oldFiles.get(path);
    const n = newFiles.get(path);
    if (o && !n) {
      const obj = getObject(repo, o.oid);
      out.push({ path, status: 'removed', additions: 0, deletions: obj ? countLines(obj.data) : 0 });
    } else if (!o && n) {
      const obj = getObject(repo, n.oid);
      out.push({ path, status: 'added', additions: obj ? countLines(obj.data) : 0, deletions: 0 });
    } else if (o && n && o.oid !== n.oid) {
      const oldObj = getObject(repo, o.oid);
      const newObj = getObject(repo, n.oid);
      const oldText = oldObj ? oldObj.data.toString('utf8') : '';
      const newText = newObj ? newObj.data.toString('utf8') : '';
      const oldLines = oldText === '' ? [] : oldText.split('\n');
      const newLines = newText === '' ? [] : newText.split('\n');
      // Cheap diff: common prefix + common suffix.
      let pre = 0;
      while (pre < oldLines.length && pre < newLines.length && oldLines[pre] === newLines[pre]) pre += 1;
      let suf = 0;
      while (
        suf < oldLines.length - pre &&
        suf < newLines.length - pre &&
        oldLines[oldLines.length - 1 - suf] === newLines[newLines.length - 1 - suf]
      ) {
        suf += 1;
      }
      const additions = Math.max(0, newLines.length - pre - suf);
      const deletions = Math.max(0, oldLines.length - pre - suf);
      out.push({ path, status: 'modified', additions: Math.max(additions, 1), deletions });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': requestId(),
    ...extra,
  });
  res.end(text);
}
function sendBuf(res: ServerResponse, status: number, body: Buffer, contentType: string, extra: Record<string, string> = {}): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'x-github-request-id': requestId(),
    ...extra,
  });
  res.end(body);
}
function sendError(res: ServerResponse, status: number, message: string, extra: Record<string, string> = {}): void {
  sendJson(res, status, { message }, extra);
}
function pathOf(req: IncomingMessage): string {
  try {
    return new URL(req.url ?? '/', 'http://entry').pathname;
  } catch {
    return '/';
  }
}
function queryOf(req: IncomingMessage): URLSearchParams {
  try {
    return new URL(req.url ?? '/', 'http://entry').searchParams;
  } catch {
    return new URLSearchParams();
  }
}
function readBody(req: IncomingMessage, limit = 64 * 1024 * 1024): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let tooBig = false;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > limit) {
        tooBig = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (tooBig) reject(new Error('body too large'));
      else resolve(Buffer.concat(chunks));
    });
    req.on('error', reject);
  });
}
async function readJsonBody(req: IncomingMessage): Promise<{ ok: true; value: unknown } | { ok: false; error: string }> {
  const buf = await readBody(req);
  if (buf.length === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(buf.toString('utf8')) };
  } catch {
    return { ok: false, error: 'malformed JSON body' };
  }
}
function authed(req: IncomingMessage): boolean {
  if (TOKEN === '') return true;
  const h = req.headers.authorization ?? '';
  return h === `Bearer ${TOKEN}`;
}
function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

// ---------------------------------------------------------------------------
// Git smart HTTP
// ---------------------------------------------------------------------------

const GIT_AGENT = 'forge/1.0';

function gitCapsUploadV0(): string {
  return `side-band-64k multi_ack_detailed thin-pack ofs-delta shallow symref=HEAD:${headRef()} agent=${GIT_AGENT}`;
}
function gitCapsReceiveV0(): string {
  return `report-status side-band-64k delete-refs ofs-delta agent=${GIT_AGENT}`;
}

function sortedRefs(repo: Repo): Array<[string, string]> {
  return [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

function v0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const parts: Buffer[] = [];
  parts.push(pktLine(`# service=${service}\n`));
  parts.push(PKT_FLUSH);
  const caps = service === 'git-upload-pack' ? gitCapsUploadV0() : gitCapsReceiveV0();
  const refs = sortedRefs(repo);
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    const headTip = repo.refs.get(headRef()) ?? '';
    // HEAD first, carrying the capabilities.
    if (headTip !== '') parts.push(pktLine(`${headTip} HEAD\0${caps}\n`));
    for (const [name, oid] of refs) {
      parts.push(pktLine(`${oid} ${name}\n`));
      const obj = getObject(repo, oid);
      if (obj !== undefined && obj.type === 'tag') {
        const tag = parseTag(obj.data);
        if (tag !== null && tag.type === 'commit') {
          parts.push(pktLine(`${tag.object} ${name}^{}\n`));
        }
      }
    }
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function v2Advertisement(): Buffer {
  const lines = [
    'version 2\n',
    'ls-refs=unborn\n',
    'fetch=shallow deepen-relative\n',
    'object-format=sha1\n',
    `agent=${GIT_AGENT}\n`,
  ];
  const parts = lines.map((l) => pktLine(l));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

/** Sideband-wrap a pack: band 1 packets, each <= 32 KiB of pack data. */
function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  const CHUNK = 32768;
  for (let off = 0; off < pack.length; off += CHUNK) {
    const slice = pack.subarray(off, Math.min(pack.length, off + CHUNK));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  if (pack.length === 0) parts.push(pktLine(Buffer.from([1])));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function handleInfoRefs(req: IncomingMessage, res: ServerResponse, owner: string, repoName: string, service: string): void {
  learnViewer(owner);
  const repo = repos.get(repoName);
  if (repo === undefined || owner !== viewerLogin) {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  if (service === 'git-upload-pack') {
    const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
    const body = isV2 ? v2Advertisement() : v0Advertisement(repo, 'git-upload-pack');
    sendBuf(res, 200, body, 'application/x-git-upload-pack-advertisement');
    return;
  }
  if (service === 'git-receive-pack') {
    const body = v0Advertisement(repo, 'git-receive-pack');
    sendBuf(res, 200, body, 'application/x-git-receive-pack-advertisement');
    return;
  }
  sendJson(res, 404, { message: 'Not Found' });
}

interface LsRefsArgs {
  peel: boolean;
  symrefs: boolean;
  unborn: boolean;
  prefixes: string[];
}

function handleUploadPack(req: IncomingMessage, res: ServerResponse, owner: string, repoName: string, body: Buffer): void {
  learnViewer(owner);
  const repo = repos.get(repoName);
  if (repo === undefined || owner !== viewerLogin) {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
  const { packets } = splitPktAndTail(body);
  const lines: string[] = [];
  let sawDelim = false;
  for (const p of packets) {
    if (p.kind === 'delim') {
      sawDelim = true;
      continue;
    }
    if (p.kind === 'flush') break;
    if (p.kind === 'data') lines.push(p.payload.toString('utf8'));
  }
  void sawDelim;
  if (isV2) {
    const command = (lines[0] ?? '').trim();
    if (command === 'command=ls-refs') {
      const args: LsRefsArgs = { peel: false, symrefs: false, unborn: false, prefixes: [] };
      for (const line of lines.slice(1)) {
        const t = line.trim();
        if (t === 'peel') args.peel = true;
        else if (t === 'symrefs') args.symrefs = true;
        else if (t === 'unborn') args.unborn = true;
        else if (t.startsWith('ref-prefix ')) args.prefixes.push(t.slice('ref-prefix '.length));
      }
      const out: Buffer[] = [];
      const refs = sortedRefs(repo);
      const include = (name: string): boolean =>
        args.prefixes.length === 0 || args.prefixes.some((p) => name.startsWith(p));
      // HEAD first, prefix-filtered, exactly like real git's
      // send_possibly_unborn_head: emitted when it resolves, or (for an
      // empty repo) when both unborn and symrefs were requested.
      const headTip = repo.refs.get(headRef());
      if (include('HEAD')) {
        if (headTip !== undefined) {
          out.push(pktLine(`${headTip} HEAD${args.symrefs ? ` symref-target:${headRef()}` : ''}\n`));
        } else if (args.unborn && args.symrefs) {
          out.push(pktLine(`unborn HEAD symref-target:${headRef()}\n`));
        }
      }
      for (const [name, oid] of refs) {
        if (!include(name)) continue;
        let line = `${oid} ${name}`;
        const obj = getObject(repo, oid);
        if (args.peel && obj !== undefined && obj.type === 'tag') {
          const tag = parseTag(obj.data);
          if (tag !== null) line += ` peeled:${tag.object}`;
        }
        out.push(pktLine(`${line}\n`));
      }
      out.push(PKT_FLUSH);
      sendBuf(res, 200, Buffer.concat(out), 'application/x-git-upload-pack-result');
      return;
    }
    if (command === 'command=fetch') {
      const wants: string[] = [];
      const haves: string[] = [];
      const shallowHeld: string[] = [];
      let depth: number | null = null;
      let deepenRelative = false;
      for (const line of lines.slice(1)) {
        const t = line.trim();
        if (t.startsWith('want ')) wants.push(t.slice(5).trim());
        else if (t.startsWith('have ')) haves.push(t.slice(5).trim());
        else if (t.startsWith('shallow ')) shallowHeld.push(t.slice(8).trim());
        else if (t.startsWith('deepen ')) depth = parseInt(t.slice(7).trim(), 10);
        else if (t === 'deepen-relative') deepenRelative = true;
      }
      const result = computeFetch(repo, wants, haves, shallowHeld, depth, deepenRelative);
      const pack = writePack([...result.objects.values()]);
      const out: Buffer[] = [];
      // Real git (and protocol-v2.txt) separates response sections with a
      // delim packet; the packfile section ends with a flush. Sections with
      // nothing to say are omitted entirely.
      if (haves.length > 0) {
        out.push(pktLine('acknowledgments\n'));
        let acked = 0;
        for (const oid of [...wants, ...haves]) {
          if (getObject(repo, oid) !== undefined) {
            out.push(pktLine(`ACK ${oid}\n`));
            acked += 1;
          }
        }
        if (acked > 0) out.push(pktLine('ready\n'));
        else out.push(pktLine('NAK\n'));
        out.push(PKT_DELIM);
      }
      if (result.shallow.length > 0 || result.unshallow.length > 0) {
        out.push(pktLine('shallow-info\n'));
        for (const s of result.shallow) out.push(pktLine(`shallow ${s}\n`));
        for (const s of result.unshallow) out.push(pktLine(`unshallow ${s}\n`));
        out.push(PKT_DELIM);
      }
      out.push(pktLine('packfile\n'));
      out.push(sidebandPack(pack));
      sendBuf(res, 200, Buffer.concat(out), 'application/x-git-upload-pack-result');
      return;
    }
    // Unknown v2 command: answer a flush (client will fail the check, but stay alive).
    sendBuf(res, 200, PKT_FLUSH, 'application/x-git-upload-pack-result');
    return;
  }
  // v0 fetch: two sections split by flush.
  const sections: string[][] = [[]];
  for (const p of packets) {
    if (p.kind === 'flush') {
      sections.push([]);
      continue;
    }
    if (p.kind === 'data') sections[sections.length - 1].push(p.payload.toString('utf8'));
  }
  const wants: string[] = [];
  const haves: string[] = [];
  const shallowHeld: string[] = [];
  let depth: number | null = null;
  for (const line of sections[0] ?? []) {
    const t = line.trim();
    const space = t.indexOf(' ');
    const first = space < 0 ? t : t.slice(0, space);
    if (first === 'want') wants.push(t.split(' ')[1] ?? '');
    else if (first === 'shallow') shallowHeld.push(t.slice(8).trim());
    else if (first === 'deepen') depth = parseInt(t.slice(7).trim(), 10);
  }
  for (const line of sections[1] ?? []) {
    const t = line.trim();
    if (t.startsWith('have ')) haves.push(t.slice(5).trim());
  }
  const result = computeFetch(repo, wants, haves, shallowHeld, depth);
  const pack = writePack([...result.objects.values()]);
  const out: Buffer[] = [];
  for (const s of result.shallow) out.push(pktLine(`shallow ${s}\n`));
  for (const s of result.unshallow) out.push(pktLine(`unshallow ${s}\n`));
  if (haves.length > 0) {
    let acked = false;
    for (const oid of haves) {
      if (getObject(repo, oid) !== undefined) {
        out.push(pktLine(`ACK ${oid}\n`));
        acked = true;
      }
    }
    if (!acked) out.push(pktLine('NAK\n'));
  } else {
    out.push(pktLine('NAK\n'));
  }
  out.push(sidebandPack(pack));
  sendBuf(res, 200, Buffer.concat(out), 'application/x-git-upload-pack-result');
}

function refsOf(repo: Repo): Array<[string, string]> {
  return sortedRefs(repo);
}

function handleReceivePack(req: IncomingMessage, res: ServerResponse, owner: string, repoName: string, body: Buffer): void {
  learnViewer(owner);
  const repo = repos.get(repoName);
  if (repo === undefined || owner !== viewerLogin) {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  const { packets, tail } = splitPktAndTail(body);
  interface Cmd {
    oldOid: string;
    newOid: string;
    ref: string;
  }
  const commands: Cmd[] = [];
  for (const p of packets) {
    if (p.kind !== 'data') continue;
    let text = p.payload.toString('utf8');
    const nul = text.indexOf('\0');
    if (nul >= 0) text = text.slice(0, nul);
    const parts = text.trim().split(' ');
    if (parts.length >= 3 && isOid(parts[0]) && isOid(parts[1])) {
      commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts[2] });
    }
  }
  const hasUpdates = commands.some((c) => c.newOid !== ZERO_OID);
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (hasUpdates && tail.length > 0) {
    try {
      const entries = readPack(tail);
      for (const e of entries) {
        if (!repo.objects.has(e.oid)) repo.objects.set(e.oid, { type: e.type, data: e.data });
      }
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'unpack error';
    }
  }
  // Apply commands one by one (partial application on mixed pushes).
  const reportLines: string[] = [];
  if (!unpackOk) {
    reportLines.push(`unpack ${unpackDetail}\n`);
    for (const c of commands) reportLines.push(`ng ${c.ref} unpack error\n`);
  } else {
    reportLines.push('unpack ok\n');
    for (const c of commands) {
      const current = repo.refs.get(c.ref) ?? null;
      if (c.newOid === ZERO_OID) {
        // Delete.
        if (current === null) {
          reportLines.push(`ng ${c.ref} reference does not exist\n`);
        } else if (c.oldOid !== ZERO_OID && c.oldOid !== current) {
          reportLines.push(`ng ${c.ref} non-fast-forward\n`);
        } else {
          repo.refs.delete(c.ref);
          reportLines.push(`ok ${c.ref}\n`);
        }
        continue;
      }
      if (c.oldOid === ZERO_OID) {
        // Create.
        if (current !== null) {
          reportLines.push(`ng ${c.ref} already exists\n`);
          continue;
        }
        if (getObject(repo, c.newOid) === undefined) {
          reportLines.push(`ng ${c.ref} missing object\n`);
          continue;
        }
        repo.refs.set(c.ref, c.newOid);
        reportLines.push(`ok ${c.ref}\n`);
        continue;
      }
      // Update: old must match, new must descend from old.
      if (current === null || current !== c.oldOid) {
        reportLines.push(`ng ${c.ref} non-fast-forward\n`);
        continue;
      }
      if (getObject(repo, c.newOid) === undefined) {
        reportLines.push(`ng ${c.ref} missing object\n`);
        continue;
      }
      if (!isAncestor(repo, c.oldOid, c.newOid)) {
        reportLines.push(`ng ${c.ref} non-fast-forward\n`);
        continue;
      }
      repo.refs.set(c.ref, c.newOid);
      reportLines.push(`ok ${c.ref}\n`);
    }
  }
  const reportText = reportLines.join('');
  // Real git's report(): the whole report buffer — pkt-lined lines PLUS its
  // terminating flush — goes through sideband band 1, and a plain flush
  // follows. The inner flush is what lets the client's reader end cleanly
  // instead of hitting EOF ("the remote end hung up").
  const inner = Buffer.concat([...reportLines.map((l) => pktLine(l)), PKT_FLUSH]);
  const out: Buffer[] = [];
  const CHUNK = 32768;
  for (let off = 0; off < inner.length; off += CHUNK) {
    const slice = inner.subarray(off, Math.min(inner.length, off + CHUNK));
    out.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  if (inner.length === 0) out.push(pktLine(Buffer.from([1])));
  out.push(PKT_FLUSH);
  sendBuf(res, 200, Buffer.concat(out), 'application/x-git-receive-pack-result');
}

// ---------------------------------------------------------------------------
// REST v3
// ---------------------------------------------------------------------------

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.dbId,
    node_id: repo.globalId('Repository', repo.dbId),
    name: repo.name,
    full_name: `${viewerName()}/${repo.name}`,
    owner: { login: viewerName(), id: 1, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: defaultBranchName(),
    created_at: repo.stamp(1),
    updated_at: repo.stamp(1),
    html_url: `https://example.invalid/${viewerName()}/${repo.name}`,
    url: `/api/v3/repos/${viewerName()}/${repo.name}`,
    has_issues: true,
  };
}
function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: issue.globalId,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => {
      const l = repo.labels.get(name);
      return { name, color: l?.color ?? 'ededed' };
    }),
    user: { login: viewerName() },
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    url: `/api/v3/repos/${viewerName()}/${repo.name}/issues/${issue.number}`,
  };
}
function prJson(repo: Repo, pr: PullRequest): Record<string, unknown> {
  return {
    id: pr.id,
    node_id: pr.globalId,
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    head: { ref: pr.head, sha: pr.headSha, label: `${viewerName()}:${pr.head}` },
    base: { ref: pr.base, sha: pr.baseSha, label: `${viewerName()}:${pr.base}` },
    merged: pr.merged,
    merged_at: pr.mergedAt,
    merge_commit_sha: pr.mergeCommitSha,
    user: { login: viewerName() },
    created_at: pr.createdAt,
  };
}
function createIssueIn(repo: Repo, title: string, body: string, labels: string[]): Issue | { error: string } {
  for (const label of labels) {
    if (!repo.labels.has(label)) return { error: `label ${label} does not exist` };
  }
  const number = repo.nextNumber;
  repo.nextNumber += 1;
  const id = repo.nextId;
  repo.nextId += 1;
  const seq = repo.nextSeq();
  const stamp = repo.stamp(seq);
  const issue: Issue = {
    number,
    id,
    globalId: repo.globalId('Issue', number),
    title,
    body,
    state: 'open',
    labels: [...labels],
    seq,
    createdAt: stamp,
    updatedAt: stamp,
  };
  repo.issues.set(number, issue);
  return issue;
}
function createPrIn(repo: Repo, title: string, body: string, head: string, base: string): PullRequest | { error: string } {
  const headSha = refTip(repo, `refs/heads/${head}`);
  const baseSha = refTip(repo, `refs/heads/${base}`);
  if (headSha === null || baseSha === null) return { error: 'head or base branch does not exist' };
  const number = repo.nextNumber;
  repo.nextNumber += 1;
  const id = repo.nextId;
  repo.nextId += 1;
  const seq = repo.nextSeq();
  const pr: PullRequest = {
    number,
    id,
    globalId: repo.globalId('PullRequest', number),
    title,
    body,
    state: 'open',
    head,
    base,
    headSha,
    baseSha,
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    seq,
    createdAt: repo.stamp(seq),
  };
  repo.prs.set(number, pr);
  return pr;
}

/** Squash-merge a PR. Returns the merge commit sha, or an error string. */
function mergePr(repo: Repo, pr: PullRequest): string | { error: string; conflict: boolean } {
  if (pr.state !== 'open') return { error: 'pull request is not open', conflict: false };
  const baseTip = refTip(repo, `refs/heads/${pr.base}`);
  const headTip = refTip(repo, `refs/heads/${pr.head}`);
  if (baseTip === null || headTip === null) return { error: 'branch does not exist', conflict: false };
  const base = mergeBase(repo, baseTip, headTip);
  const baseTree = base !== null ? commitOf(repo, base)?.tree ?? null : null;
  const baseTipTree = commitOf(repo, baseTip)?.tree ?? null;
  const headTree = commitOf(repo, headTip)?.tree ?? null;
  if (baseTipTree === null || headTree === null) return { error: 'missing tree', conflict: false };
  const baseFiles = baseTree !== null ? flattenTree(repo, baseTree) : new Map();
  const baseTipFiles = flattenTree(repo, baseTipTree);
  const headFiles = flattenTree(repo, headTree);
  // Conflict: a path changed in both base-tip and head (vs merge-base) to different blobs.
  for (const [path, headFile] of headFiles) {
    const baseFile = baseFiles.get(path);
    const tipFile = baseTipFiles.get(path);
    const headChanged = baseFile?.oid !== headFile.oid;
    const tipChanged = baseFile?.oid !== tipFile?.oid;
    if (headChanged && tipChanged && tipFile?.oid !== headFile.oid) {
      return { error: 'merge conflict', conflict: true };
    }
  }
  for (const [path, baseFile] of baseFiles) {
    if (headFiles.has(path)) continue;
    const tipFile = baseTipFiles.get(path);
    if (tipFile?.oid !== baseFile.oid) {
      // Deleted on head, changed on base-tip -> conflict.
      return { error: 'merge conflict', conflict: true };
    }
  }
  // Result tree: base-tip tree with head's changes overlaid.
  const resultFiles = new Map(baseTipFiles);
  for (const [path, headFile] of headFiles) resultFiles.set(path, headFile);
  for (const path of baseFiles.keys()) {
    if (!headFiles.has(path) && baseTipFiles.get(path)?.oid === baseFiles.get(path)?.oid) {
      resultFiles.delete(path); // deleted on head, unchanged on base-tip
    }
  }
  const treeOid = buildTreeFromFiles(repo, resultFiles);
  const message = `${pr.title} (#${pr.number})`;
  const mergeSha = makeCommit(repo, treeOid, [baseTip], message);
  repo.refs.set(`refs/heads/${pr.base}`, mergeSha);
  const seq = repo.nextSeq();
  pr.state = 'closed';
  pr.merged = true;
  pr.mergedAt = repo.stamp(seq);
  pr.mergeCommitSha = mergeSha;
  return mergeSha;
}

function prFiles(repo: Repo, pr: PullRequest): FileChange[] {
  const baseTip = refTip(repo, `refs/heads/${pr.base}`);
  const headTip = refTip(repo, `refs/heads/${pr.head}`);
  if (baseTip === null || headTip === null) return [];
  const base = mergeBase(repo, baseTip, headTip);
  const baseTree = base !== null ? commitOf(repo, base)?.tree ?? null : null;
  const headTree = commitOf(repo, headTip)?.tree ?? null;
  if (headTree === null) return [];
  const baseFiles = baseTree !== null ? flattenTree(repo, baseTree) : new Map();
  const headFiles = flattenTree(repo, headTree);
  return diffFiles(repo, baseFiles, headFiles);
}

/** Commits reachable from a ref (tip first), as REST commit shapes. */
function commitsJson(repo: Repo, refName: string | null): Array<Record<string, unknown>> {
  const ref = refName !== null ? `refs/heads/${refName}` : headRef();
  const tip = refTip(repo, ref);
  if (tip === null) return [];
  const out: Array<Record<string, unknown>> = [];
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length > 0) {
    const oid = stack.pop()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const info = commitOf(repo, oid);
    if (info === null) continue;
    out.push({
      sha: oid,
      // GitHub's API returns the message without the trailing newline that
      // the raw commit object carries.
      commit: { message: info.message.replace(/\n+$/, ''), author: { name: viewerName() }, committer: { name: viewerName() } },
    });
    for (const p of info.parents) stack.push(p);
  }
  return out;
}

function getRepoOr404(res: ServerResponse, owner: string, repoName: string): Repo | null {
  if (owner !== viewerLogin) {
    sendError(res, 404, 'Not Found');
    return null;
  }
  const repo = repos.get(repoName);
  if (repo === undefined) {
    sendError(res, 404, 'Not Found');
    return null;
  }
  return repo;
}

async function handleRest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const method = req.method ?? 'GET';
  const path = pathOf(req);
  const query = queryOf(req);
  const segs = path.split('/').filter((s) => s !== '');
  // segs[0] === 'api', segs[1] === 'v3'
  // GET /api/v3/ root (starter behaviour: 200 without auth).
  if (method === 'GET' && (path === '/api/v3' || path === '/api/v3/')) {
    sendJson(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
    return;
  }
  if (!authed(req)) {
    sendError(res, 401, 'Bad credentials');
    return;
  }
  // GET /api/v3/meta
  if (method === 'GET' && path === '/api/v3/meta') {
    sendJson(res, 200, { verifiable_password_authentication: true, installed_version: '1.0.0' });
    return;
  }
  // POST /api/v3/user/repos
  if (method === 'POST' && path === '/api/v3/user/repos') {
    const parsed = await readJsonBody(req);
    if (!parsed.ok) {
      sendError(res, 400, parsed.error);
      return;
    }
    const body = isRecord(parsed.value) ? parsed.value : {};
    const name = typeof body.name === 'string' ? body.name : '';
    if (name === '') {
      sendError(res, 422, 'name is required');
      return;
    }
    if (repos.has(name)) {
      sendError(res, 422, 'Repository already exists');
      return;
    }
    const repo = new Repo(
      name,
      nextDbId,
      typeof body.description === 'string' ? body.description : '',
      body.private === true,
    );
    nextDbId += 1;
    repos.set(name, repo);
    sendJson(res, 201, repoJson(repo));
    return;
  }
  // GET /api/v3/user/repos (paginated)
  if (method === 'GET' && path === '/api/v3/user/repos') {
    const perPage = Math.max(1, Math.min(100, parseInt(query.get('per_page') ?? '30', 10) || 30));
    const page = Math.max(1, parseInt(query.get('page') ?? '1', 10) || 1);
    const all = [...repos.values()];
    const slice = all.slice((page - 1) * perPage, page * perPage);
    const extra: Record<string, string> = {};
    if (page * perPage < all.length) {
      const host = req.headers.host ?? 'localhost';
      const proto = 'http';
      extra.link = `<${proto}://${host}/api/v3/user/repos?per_page=${perPage}&page=${page + 1}>; rel="next"`;
    }
    sendJson(res, 200, slice.map((r) => repoJson(r)), extra);
    return;
  }
  // /api/v3/repos/{owner}/{repo}[/...]
  if (segs.length >= 4 && segs[0] === 'api' && segs[1] === 'v3' && segs[2] === 'repos') {
    const owner = decodeURIComponent(segs[3]);
    const repoName = decodeURIComponent(segs[4]);
    learnViewer(owner);
    const rest = segs.slice(5);
    // GET /repos/{o}/{r}
    if (rest.length === 0) {
      if (method === 'GET') {
        const repo = getRepoOr404(res, owner, repoName);
        if (repo !== null) sendJson(res, 200, repoJson(repo));
        return;
      }
      if (method === 'PATCH') {
        const repo = getRepoOr404(res, owner, repoName);
        if (repo === null) return;
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          sendError(res, 400, parsed.error);
          return;
        }
        const body = isRecord(parsed.value) ? parsed.value : {};
        if (typeof body.description === 'string') repo.description = body.description;
        sendJson(res, 200, repoJson(repo));
        return;
      }
      if (method === 'DELETE') {
        const repo = getRepoOr404(res, owner, repoName);
        if (repo === null) return;
        repos.delete(repoName);
        res.writeHead(204, { 'x-github-request-id': requestId() });
        res.end();
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    const repo = getRepoOr404(res, owner, repoName);
    if (repo === null) return;
    const sub = rest[0];
    // POST /git/refs
    if (sub === 'git' && rest[1] === 'refs' && method === 'POST') {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        sendError(res, 400, parsed.error);
        return;
      }
      const body = isRecord(parsed.value) ? parsed.value : {};
      const ref = typeof body.ref === 'string' ? body.ref : '';
      const sha = typeof body.sha === 'string' ? body.sha : '';
      if (!ref.startsWith('refs/') || !isOid(sha)) {
        sendError(res, 422, 'invalid ref or sha');
        return;
      }
      repo.refs.set(ref, sha);
      sendJson(res, 201, { ref, object: { sha }, url: `/api/v3/repos/${owner}/${repoName}/git/refs/${encodeURIComponent(ref)}` });
      return;
    }
    // GET /branches
    if (sub === 'branches' && method === 'GET') {
      const out: Array<Record<string, unknown>> = [];
      for (const [name, oid] of repo.refs) {
        if (name.startsWith('refs/heads/')) out.push({ name: name.slice('refs/heads/'.length), commit: { sha: oid } });
      }
      sendJson(res, 200, out);
      return;
    }
    // GET /commits
    if (sub === 'commits' && method === 'GET') {
      const shaParam = query.get('sha');
      sendJson(res, 200, commitsJson(repo, shaParam));
      return;
    }
    // contents
    if (sub === 'contents') {
      const contentPath = rest.slice(1).map((s) => decodeURIComponent(s)).join('/');
      if (method === 'PUT') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          sendError(res, 400, parsed.error);
          return;
        }
        const body = isRecord(parsed.value) ? parsed.value : {};
        const message = typeof body.message === 'string' ? body.message : 'update';
        const contentB64 = typeof body.content === 'string' ? body.content : '';
        const branch = typeof body.branch === 'string' ? body.branch : defaultBranchName();
        const shaParam = typeof body.sha === 'string' ? body.sha : null;
        let bytes: Buffer;
        try {
          bytes = Buffer.from(contentB64.replace(/[\r\n\t ]/g, ''), 'base64');
        } catch {
          sendError(res, 400, 'invalid base64 content');
          return;
        }
        const refName = `refs/heads/${branch}`;
        const tip = refTip(repo, refName);
        const files = tip !== null ? flattenTree(repo, commitOf(repo, tip)?.tree ?? '') : new Map<string, { oid: string; mode: string }>();
        const existing = files.get(contentPath);
        if (shaParam !== null) {
          if (existing === undefined || existing.oid !== shaParam) {
            sendError(res, 409, 'sha does not match the current blob');
            return;
          }
        }
        const isUpdate = existing !== undefined;
        const blobOid = storeObject(repo, 'blob', bytes);
        files.set(contentPath, { oid: blobOid, mode: '100644' });
        const treeOid = buildTreeFromFiles(repo, files);
        const parents = tip !== null ? [tip] : [];
        const commitSha = makeCommit(repo, treeOid, parents, message);
        repo.refs.set(refName, commitSha);
        sendJson(res, isUpdate ? 200 : 201, {
          content: { name: contentPath.split('/').pop() ?? '', path: contentPath, sha: blobOid, size: bytes.length, encoding: 'base64', type: 'file' },
          commit: { sha: commitSha, message },
        });
        return;
      }
      if (method === 'GET') {
        const refParam = query.get('ref');
        const refName = refParam !== null ? `refs/heads/${refParam}` : headRef();
        const tip = refTip(repo, refName);
        if (tip === null) {
          sendError(res, 404, 'Not Found');
          return;
        }
        const treeOid = commitOf(repo, tip)?.tree;
        if (treeOid === undefined) {
          sendError(res, 404, 'Not Found');
          return;
        }
        const files = flattenTree(repo, treeOid);
        const file = files.get(contentPath);
        if (file !== undefined) {
          const obj = getObject(repo, file.oid);
          const data = obj?.data ?? Buffer.alloc(0);
          sendJson(res, 200, {
            type: 'file',
            encoding: 'base64',
            size: data.length,
            name: contentPath.split('/').pop() ?? '',
            path: contentPath,
            sha: file.oid,
            content: data.toString('base64'),
          });
          return;
        }
        // Directory listing: immediate children of contentPath.
        const prefix = contentPath === '' ? '' : `${contentPath}/`;
        const children = new Map<string, { type: string; oid: string }>();
        for (const [p, f] of files) {
          if (!p.startsWith(prefix)) continue;
          const restPath = p.slice(prefix.length);
          const slash = restPath.indexOf('/');
          if (slash < 0) children.set(restPath, { type: 'file', oid: f.oid });
          else {
            const dirName = restPath.slice(0, slash);
            if (!children.has(dirName)) {
              // Directory sha: the subtree oid.
              children.set(dirName, { type: 'dir', oid: subtreeOid(repo, treeOid, `${prefix}${dirName}`) });
            }
          }
        }
        if (children.size === 0) {
          sendError(res, 404, 'Not Found');
          return;
        }
        const out = [...children.entries()].map(([name, c]) => ({
          type: c.type,
          name,
          path: `${prefix}${name}`,
          sha: c.oid,
        }));
        sendJson(res, 200, out);
        return;
      }
      if (method === 'DELETE') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          sendError(res, 400, parsed.error);
          return;
        }
        const body = isRecord(parsed.value) ? parsed.value : {};
        const message = typeof body.message === 'string' ? body.message : 'delete';
        const shaParam = typeof body.sha === 'string' ? body.sha : null;
        const tip = refTip(repo, headRef());
        if (tip === null) {
          sendError(res, 404, 'Not Found');
          return;
        }
        const files = flattenTree(repo, commitOf(repo, tip)?.tree ?? '');
        const existing = files.get(contentPath);
        if (existing === undefined || (shaParam !== null && existing.oid !== shaParam)) {
          sendError(res, 404, 'Not Found');
          return;
        }
        files.delete(contentPath);
        const treeOid = buildTreeFromFiles(repo, files);
        const commitSha = makeCommit(repo, treeOid, [tip], message);
        repo.refs.set(headRef(), commitSha);
        sendJson(res, 200, { commit: { sha: commitSha, message } });
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    // POST /labels
    if (sub === 'labels' && method === 'POST') {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        sendError(res, 400, parsed.error);
        return;
      }
      const body = isRecord(parsed.value) ? parsed.value : {};
      const name = typeof body.name === 'string' ? body.name : '';
      const color = typeof body.color === 'string' ? body.color : 'ededed';
      if (name === '') {
        sendError(res, 422, 'name is required');
        return;
      }
      repo.labels.set(name, { name, color });
      sendJson(res, 201, { name, color, description: '' });
      return;
    }
    // issues
    if (sub === 'issues') {
      const numSeg = rest[1];
      if (numSeg === undefined) {
        if (method === 'POST') {
          const parsed = await readJsonBody(req);
          if (!parsed.ok) {
            sendError(res, 400, parsed.error);
            return;
          }
          const body = isRecord(parsed.value) ? parsed.value : {};
          const title = typeof body.title === 'string' ? body.title : '';
          const bodyText = typeof body.body === 'string' ? body.body : '';
          const labels = Array.isArray(body.labels) ? body.labels.filter((l): l is string => typeof l === 'string') : [];
          const created = createIssueIn(repo, title, bodyText, labels);
          if ('error' in created) {
            sendError(res, 422, created.error);
            return;
          }
          sendJson(res, 201, issueJson(repo, created));
          return;
        }
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          const sort = query.get('sort') ?? 'created';
          const direction = query.get('direction') ?? 'desc';
          const perPage = parseInt(query.get('per_page') ?? '100', 10) || 100;
          let list = [...repo.issues.values()];
          if (state !== 'all') list = list.filter((i) => i.state === state);
          list.sort((a, b) => {
            const cmp = sort === 'created' ? a.seq - b.seq : a.number - b.number;
            return direction === 'asc' ? cmp : -cmp;
          });
          sendJson(res, 200, list.slice(0, perPage).map((i) => issueJson(repo, i)));
          return;
        }
        sendError(res, 404, 'Not Found');
        return;
      }
      const num = parseInt(numSeg, 10);
      if (!Number.isInteger(num)) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const issue = repo.issues.get(num);
      if (rest[2] === 'comments') {
        if (issue === undefined) {
          sendError(res, 404, 'Not Found');
          return;
        }
        if (method === 'POST') {
          const parsed = await readJsonBody(req);
          if (!parsed.ok) {
            sendError(res, 400, parsed.error);
            return;
          }
          const body = isRecord(parsed.value) ? parsed.value : {};
          const text = typeof body.body === 'string' ? body.body : '';
          const id = repo.nextId;
          repo.nextId += 1;
          const seq = repo.nextSeq();
          const comment: Comment = {
            id,
            globalId: repo.globalId('IssueComment', id),
            body: text,
            seq,
            createdAt: repo.stamp(seq),
          };
          const list = repo.comments.get(num) ?? [];
          list.push(comment);
          repo.comments.set(num, list);
          sendJson(res, 201, { id: comment.id, node_id: comment.globalId, body: comment.body, created_at: comment.createdAt, user: { login: viewerName() } });
          return;
        }
        if (method === 'GET') {
          const list = repo.comments.get(num) ?? [];
          sendJson(res, 200, list.map((c) => ({ id: c.id, node_id: c.globalId, body: c.body, created_at: c.createdAt, user: { login: viewerName() } })));
          return;
        }
        sendError(res, 404, 'Not Found');
        return;
      }
      if (rest.length > 2) {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (issue === undefined) {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (method === 'GET') {
        sendJson(res, 200, issueJson(repo, issue));
        return;
      }
      if (method === 'PATCH') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          sendError(res, 400, parsed.error);
          return;
        }
        const body = isRecord(parsed.value) ? parsed.value : {};
        if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
        if (typeof body.title === 'string') issue.title = body.title;
        if (typeof body.body === 'string') issue.body = body.body;
        const seq = repo.nextSeq();
        issue.updatedAt = repo.stamp(seq);
        sendJson(res, 200, issueJson(repo, issue));
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    // pulls
    if (sub === 'pulls') {
      const numSeg = rest[1];
      if (numSeg === undefined) {
        if (method === 'POST') {
          const parsed = await readJsonBody(req);
          if (!parsed.ok) {
            sendError(res, 400, parsed.error);
            return;
          }
          const body = isRecord(parsed.value) ? parsed.value : {};
          const title = typeof body.title === 'string' ? body.title : '';
          const bodyText = typeof body.body === 'string' ? body.body : '';
          const head = typeof body.head === 'string' ? body.head : '';
          const base = typeof body.base === 'string' ? body.base : '';
          const created = createPrIn(repo, title, bodyText, head, base);
          if ('error' in created) {
            sendError(res, 422, created.error);
            return;
          }
          sendJson(res, 201, prJson(repo, created));
          return;
        }
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          const perPage = parseInt(query.get('per_page') ?? '100', 10) || 100;
          let list = [...repo.prs.values()];
          if (state !== 'all') list = list.filter((p) => p.state === state);
          list.sort((a, b) => a.number - b.number);
          sendJson(res, 200, list.slice(0, perPage).map((p) => prJson(repo, p)));
          return;
        }
        sendError(res, 404, 'Not Found');
        return;
      }
      const num = parseInt(numSeg, 10);
      if (!Number.isInteger(num)) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const pr = repo.prs.get(num);
      if (rest[2] === 'files' && method === 'GET') {
        if (pr === undefined) {
          sendError(res, 404, 'Not Found');
          return;
        }
        const files = prFiles(repo, pr);
        sendJson(res, 200, files.map((f) => ({
          filename: f.path,
          status: f.status === 'removed' ? 'removed' : f.status,
          additions: f.additions,
          deletions: f.deletions,
          changes: f.additions + f.deletions,
        })));
        return;
      }
      if (rest[2] === 'merge' && method === 'PUT') {
        if (pr === undefined) {
          sendError(res, 404, 'Not Found');
          return;
        }
        await readBody(req).catch(() => Buffer.alloc(0));
        const result = mergePr(repo, pr);
        if (typeof result === 'object') {
          if (result.conflict) sendError(res, 405, result.error);
          else sendError(res, 422, result.error);
          return;
        }
        sendJson(res, 200, { merged: true, sha: result, message: `Merged pull request #${pr.number}` });
        return;
      }
      if (rest.length > 2) {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (pr === undefined) {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (method === 'GET') {
        sendJson(res, 200, prJson(repo, pr));
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }
  sendError(res, 404, 'Not Found');
}

/** Find a subtree oid for a directory path (used for directory listings). */
function subtreeOid(repo: Repo, treeOid: string, dirPath: string): string {
  const parts = dirPath.split('/').filter((p) => p !== '');
  let cur = treeOid;
  for (const part of parts) {
    let found: string | null = null;
    for (const e of treeEntriesOf(repo, cur)) {
      if (e.mode === '40000' && e.name === part) {
        found = e.oid;
        break;
      }
    }
    if (found === null) return ZERO_OID;
    cur = found;
  }
  return cur;
}

// ---------------------------------------------------------------------------
// GraphQL v4 (mini parser + executor for the documents gh / github-mcp send)
// ---------------------------------------------------------------------------

type GqlValue =
  | { kind: 'variable'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; values: GqlValue[] }
  | { kind: 'object'; fields: Array<{ name: string; value: GqlValue }> };

interface GqlSelection {
  alias: string | null;
  name: string;
  args: Array<{ name: string; value: GqlValue }>;
  selections: GqlSelection[] | null;
  fragmentType: string | null; // for `... on Type`
}
interface GqlOperation {
  type: 'query' | 'mutation';
  name: string | null;
  selections: GqlSelection[];
}

function gqlLex(src: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === ' ' || c === '\n' || c === '\r' || c === '\t' || c === ',') {
      i += 1;
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (src.startsWith('...', i)) {
      tokens.push('...');
      i += 3;
      continue;
    }
    if ('{}()[]:!=$@'.includes(c)) {
      tokens.push(c);
      i += 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          out += src[j + 1];
          j += 2;
        } else {
          out += src[j];
          j += 1;
        }
      }
      tokens.push(JSON.stringify(out));
      i = j + 1;
      continue;
    }
    let j = i;
    while (j < src.length && /[A-Za-z0-9_.-]/.test(src[j])) j += 1;
    if (j === i) throw new Error(`unexpected char ${c}`);
    tokens.push(src.slice(i, j));
    i = j;
  }
  return tokens;
}

class GqlParser {
  tokens: string[];
  pos = 0;
  constructor(src: string) {
    this.tokens = gqlLex(src);
  }
  peek(): string | undefined {
    return this.tokens[this.pos];
  }
  next(): string {
    const t = this.tokens[this.pos];
    this.pos += 1;
    return t;
  }
  expect(t: string): void {
    const got = this.next();
    if (got !== t) throw new Error(`expected ${t}, got ${got}`);
  }
  parseDocument(): GqlOperation[] {
    const ops: GqlOperation[] = [];
    while (this.pos < this.tokens.length) {
      ops.push(this.parseOperation());
    }
    return ops;
  }
  parseOperation(): GqlOperation {
    let type: 'query' | 'mutation' = 'query';
    const t = this.peek();
    if (t === 'query' || t === 'mutation') {
      type = this.next() as 'query' | 'mutation';
    }
    let name: string | null = null;
    if (this.peek() !== undefined && this.peek() !== '{' && this.peek() !== '(') {
      name = this.next();
    }
    // Variable definitions: ($x: Type!, ...) — skip.
    if (this.peek() === '(') {
      let depth = 0;
      while (this.pos < this.tokens.length) {
        const tok = this.next();
        if (tok === '(' || tok === '[') depth += 1;
        if (tok === ')' || tok === ']') {
          depth -= 1;
          if (depth === 0) break;
        }
      }
    }
    const selections = this.parseSelectionSet();
    return { type, name, selections };
  }
  parseSelectionSet(): GqlSelection[] {
    this.expect('{');
    const out: GqlSelection[] = [];
    while (this.peek() !== '}' && this.peek() !== undefined) {
      out.push(this.parseSelection());
    }
    this.expect('}');
    return out;
  }
  parseSelection(): GqlSelection {
    if (this.peek() === '...') {
      this.next();
      let fragmentType: string | null = null;
      if (this.peek() === 'on') {
        this.next();
        fragmentType = this.next();
      } else {
        // Named fragment spread (not used by the suite); skip name.
        this.next();
      }
      const selections = this.parseSelectionSet();
      return { alias: null, name: '', args: [], selections, fragmentType };
    }
    let alias: string | null = null;
    let name = this.next();
    if (this.peek() === ':') {
      this.next();
      alias = name;
      name = this.next();
    }
    const args: Array<{ name: string; value: GqlValue }> = [];
    if (this.peek() === '(') {
      this.next();
      while (this.peek() !== ')') {
        const argName = this.next();
        this.expect(':');
        args.push({ name: argName, value: this.parseValue() });
      }
      this.next();
    }
    let selections: GqlSelection[] | null = null;
    if (this.peek() === '{') selections = this.parseSelectionSet();
    return { alias, name, args, selections, fragmentType: null };
  }
  parseValue(): GqlValue {
    const t = this.next();
    if (t === '$') return { kind: 'variable', name: this.next() };
    if (t === '[') {
      const values: GqlValue[] = [];
      while (this.peek() !== ']') values.push(this.parseValue());
      this.next();
      return { kind: 'list', values };
    }
    if (t === '{') {
      const fields: Array<{ name: string; value: GqlValue }> = [];
      while (this.peek() !== '}') {
        const name = this.next();
        this.expect(':');
        fields.push({ name, value: this.parseValue() });
      }
      this.next();
      return { kind: 'object', fields };
    }
    if (t === 'true') return { kind: 'boolean', value: true };
    if (t === 'false') return { kind: 'boolean', value: false };
    if (t === 'null') return { kind: 'null' };
    if (t.startsWith('"')) return { kind: 'string', value: JSON.parse(t) as string };
    if (/^-?\d+$/.test(t)) return { kind: 'int', value: parseInt(t, 10) };
    if (/^-?\d+\.\d+$/.test(t)) return { kind: 'float', value: parseFloat(t) };
    return { kind: 'enum', value: t };
  }
}

function evalValue(v: GqlValue, variables: Record<string, unknown>): unknown {
  switch (v.kind) {
    case 'variable':
      return variables[v.name] ?? null;
    case 'string':
    case 'int':
    case 'float':
    case 'boolean':
      return v.value;
    case 'null':
      return null;
    case 'enum':
      return v.value;
    case 'list':
      return v.values.map((x) => evalValue(x, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const f of v.fields) out[f.name] = evalValue(f.value, variables);
      return out;
    }
  }
}

const ISSUE_FIELDS = ['id', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'author', 'repository', 'comments'];
const PR_FIELDS = ['id', 'number', 'title', 'body', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files', 'author', 'createdAt', 'mergedAt', 'mergeCommit', 'url'];
const REPO_FIELDS = ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'url', 'createdAt', 'description', 'private', 'isPrivate'];
const SEARCH_ENUM = ['CODE', 'DISCUSSION', 'ISSUE', 'REPOSITORY', 'USER'];

function gqlError(message: string): { message: string } {
  return { message };
}

interface GqlCtx {
  variables: Record<string, unknown>;
  errors: Array<{ message: string }>;
}

function argValue(sel: GqlSelection, name: string, ctx: GqlCtx): unknown {
  const a = sel.args.find((x) => x.name === name);
  if (a === undefined) return undefined;
  return evalValue(a.value, ctx.variables);
}

function resolveSelections(
  typeName: string,
  obj: unknown,
  selections: GqlSelection[],
  ctx: GqlCtx,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    if (sel.fragmentType !== null) {
      if (sel.fragmentType !== typeName && !(typeName === 'Node' && sel.fragmentType === 'Repository')) continue;
      if (sel.selections !== null) {
        Object.assign(out, resolveSelections(typeName, obj, sel.selections, ctx));
      }
      continue;
    }
    const key = sel.alias ?? sel.name;
    const value = resolveField(typeName, obj, sel, ctx);
    if (value === undefined && ctx.errors.length > 0) {
      // Field error: keep the key out; the caller reports errors.
      continue;
    }
    out[key] = value;
  }
  return out;
}

function resolveField(typeName: string, obj: unknown, sel: GqlSelection, ctx: GqlCtx): unknown {
  const name = sel.name;
  if (typeName === 'Query') {
    if (name === 'viewer') {
      const login = viewerName();
      return sel.selections !== null ? resolveSelections('User', { login }, sel.selections, ctx) : { login };
    }
    if (name === 'repository') {
      const owner = argValue(sel, 'owner', ctx) as string;
      const repoName = argValue(sel, 'name', ctx) as string;
      if (owner !== viewerLogin) return null;
      const repo = repos.get(repoName);
      if (repo === undefined) return null;
      return sel.selections !== null ? resolveSelections('Repository', repo, sel.selections, ctx) : null;
    }
    if (name === 'node') {
      const id = argValue(sel, 'id', ctx) as string;
      const decoded = typeof id === 'string' ? b64decode(id) : null;
      if (decoded !== null && decoded.startsWith('Repository:')) {
        const dbId = parseInt(decoded.slice('Repository:'.length), 10);
        const repo = [...repos.values()].find((r) => r.dbId === dbId);
        if (repo !== undefined) {
          return sel.selections !== null ? resolveSelections('Repository', repo, sel.selections, ctx) : null;
        }
      }
      return null;
    }
    if (name === '__type') {
      const typeArg = argValue(sel, 'name', ctx) as string;
      const typeObj = { __typeName: typeArg };
      return sel.selections !== null ? resolveSelections('__Type', typeObj, sel.selections, ctx) : null;
    }
    ctx.errors.push(gqlError(`Cannot query field "${name}" on type "Query".`));
    return undefined;
  }
  if (typeName === 'User') {
    if (name === 'login') return (obj as { login: string }).login;
    ctx.errors.push(gqlError(`Cannot query field "${name}" on type "User". noSuchFieldOn${name === 'noSuchFieldOnViewer' ? 'Viewer' : 'User'}`));
    return undefined;
  }
  if (typeName === '__Type') {
    const t = (obj as { __typeName: string }).__typeName;
    if (name === 'fields') {
      const list = t === 'Issue' ? ISSUE_FIELDS : t === 'PullRequest' ? PR_FIELDS : t === 'Repository' ? REPO_FIELDS : [];
      return list.map((f) => ({ name: f }));
    }
    if (name === 'enumValues') {
      if (t === 'SearchType') return SEARCH_ENUM.map((n) => ({ name: n }));
      return [];
    }
    if (name === 'name') return t;
    ctx.errors.push(gqlError(`Cannot query field "${name}" on type "__Type".`));
    return undefined;
  }
  if (typeName === 'Repository') {
    const repo = obj as Repo;
    switch (name) {
      case 'id':
        return repo.globalId('Repository', repo.dbId);
      case 'databaseId':
        return repo.dbId;
      case 'name':
        return repo.name;
      case 'nameWithOwner':
        return `${viewerName()}/${repo.name}`;
      case 'owner':
        return sel.selections !== null ? resolveSelections('User', { login: viewerName() }, sel.selections, ctx) : { login: viewerName() };
      case 'defaultBranchRef':
        return sel.selections !== null ? resolveSelections('Ref', { name: defaultBranchName() }, sel.selections, ctx) : { name: defaultBranchName() };
      case 'viewerPermission':
        return 'ADMIN';
      case 'hasIssuesEnabled':
        return true;
      case 'description':
        return repo.description;
      case 'private':
      case 'isPrivate':
        return repo.isPrivate;
      case 'url':
        return `/api/v3/repos/${viewerName()}/${repo.name}`;
      case 'createdAt':
        return repo.stamp(1);
      case 'issue': {
        const num = argValue(sel, 'number', ctx) as number;
        const issue = repo.issues.get(num);
        if (issue === undefined) return null;
        return sel.selections !== null ? resolveSelections('Issue', issue, sel.selections, ctx) : null;
      }
      case 'issues': {
        const first = argValue(sel, 'first', ctx) as number | undefined;
        const states = argValue(sel, 'states', ctx) as string[] | undefined;
        const orderBy = argValue(sel, 'orderBy', ctx) as Record<string, unknown> | undefined;
        const after = argValue(sel, 'after', ctx) as string | null | undefined;
        let list = [...repo.issues.values()];
        if (states !== undefined) {
          const want = new Set(states.map((s) => String(s).toLowerCase()));
          list = list.filter((i) => want.has(i.state));
        }
        // CREATED_AT DESC, ties by number DESC.
        list.sort((a, b) => {
          const dir = orderBy !== undefined && String(orderBy.direction ?? 'DESC') === 'ASC' ? 1 : -1;
          if (a.seq !== b.seq) return (a.seq - b.seq) * dir;
          return (a.number - b.number) * dir;
        });
        let startIdx = 0;
        if (after !== undefined && after !== null && typeof after === 'string') {
          const decoded = b64decode(after);
          if (decoded !== null && decoded.startsWith('cursor:')) {
            const lastNum = parseInt(decoded.slice('cursor:'.length), 10);
            const idx = list.findIndex((i) => i.number === lastNum);
            if (idx >= 0) startIdx = idx + 1;
          }
        }
        const page = first !== undefined ? list.slice(startIdx, startIdx + first) : list.slice(startIdx);
        const hasNext = startIdx + page.length < list.length;
        const endCursor = page.length > 0 ? b64encode(`cursor:${page[page.length - 1].number}`) : null;
        const nodes = page.map((issue) => (sel.selections !== null ? resolveIssueNodes(sel, issue, ctx) : null));
        return sel.selections !== null ? resolveConnection(sel, nodes, hasNext, endCursor, ctx) : null;
      }
      case 'pullRequests': {
        const first = argValue(sel, 'first', ctx) as number | undefined;
        let list = [...repo.prs.values()];
        list.sort((a, b) => a.number - b.number);
        if (first !== undefined) list = list.slice(0, first);
        const nodes = list.map((pr) => (sel.selections !== null ? resolvePrNodes(sel, pr, ctx) : null));
        return sel.selections !== null ? resolveConnection(sel, nodes, false, null, ctx) : null;
      }
      case 'pullRequest': {
        const num = argValue(sel, 'number', ctx) as number;
        const pr = repo.prs.get(num);
        if (pr === undefined) return null;
        return sel.selections !== null ? resolveSelections('PullRequest', pr, sel.selections, ctx) : null;
      }
      default:
        ctx.errors.push(gqlError(`Cannot query field "${name}" on type "Repository".`));
        return undefined;
    }
  }
  if (typeName === 'Issue') {
    const issue = obj as Issue;
    switch (name) {
      case 'id':
        return issue.globalId;
      case 'number':
        return issue.number;
      case 'title':
        return issue.title;
      case 'state':
        return issue.state === 'open' ? 'OPEN' : 'CLOSED';
      case 'body':
        return issue.body;
      case 'url':
        return '';
      case 'createdAt':
        return issue.createdAt;
      default:
        ctx.errors.push(gqlError(`Cannot query field "${name}" on type "Issue".`));
        return undefined;
    }
  }
  if (typeName === 'PullRequest') {
    const pr = obj as PullRequest;
    switch (name) {
      case 'id':
        return pr.globalId;
      case 'number':
        return pr.number;
      case 'title':
        return pr.title;
      case 'body':
        return pr.body;
      case 'headRefName':
        return pr.head;
      case 'baseRefName':
        return pr.base;
      case 'mergeable':
        return 'MERGEABLE';
      case 'state':
        return pr.merged ? 'MERGED' : pr.state === 'open' ? 'OPEN' : 'CLOSED';
      case 'merged':
        return pr.merged;
      case 'mergedAt':
        return pr.mergedAt;
      case 'files': {
        // Find the repo that owns this PR.
        const repo = [...repos.values()].find((r) => r.prs.get(pr.number) === pr);
        if (repo === undefined) return { nodes: [] };
        const files = prFiles(repo, pr);
        const first = argValue(sel, 'first', ctx) as number | undefined;
        const nodes = (first !== undefined ? files.slice(0, first) : files).map((f) => ({ path: f.path }));
        return sel.selections !== null ? resolveConnection(sel, nodes, false, null, ctx) : null;
      }
      default:
        ctx.errors.push(gqlError(`Cannot query field "${name}" on type "PullRequest".`));
        return undefined;
    }
  }
  if (typeName === 'Ref') {
    if (name === 'name') return (obj as { name: string }).name;
    ctx.errors.push(gqlError(`Cannot query field "${name}" on type "Ref".`));
    return undefined;
  }
  ctx.errors.push(gqlError(`Cannot query field "${name}" on type "${typeName}".`));
  return undefined;
}

function resolveIssueNodes(sel: GqlSelection, issue: Issue, ctx: GqlCtx): Record<string, unknown> | null {
  // sel.selections are the fields of the connection; find `nodes` sub-selection.
  const nodesSel = sel.selections?.find((s) => s.name === 'nodes');
  if (nodesSel?.selections === null || nodesSel === undefined) return null;
  return resolveSelections('Issue', issue, nodesSel.selections ?? [], ctx);
}
function resolvePrNodes(sel: GqlSelection, pr: PullRequest, ctx: GqlCtx): Record<string, unknown> | null {
  const nodesSel = sel.selections?.find((s) => s.name === 'nodes');
  if (nodesSel?.selections === null || nodesSel === undefined) return null;
  return resolveSelections('PullRequest', pr, nodesSel.selections ?? [], ctx);
}
function resolveConnection(
  sel: GqlSelection,
  nodes: Array<Record<string, unknown> | null>,
  hasNextPage: boolean,
  endCursor: string | null,
  _ctx: GqlCtx,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sub of sel.selections ?? []) {
    if (sub.name === 'nodes') out.nodes = nodes;
    else if (sub.name === 'pageInfo') {
      const pi: Record<string, unknown> = {};
      for (const f of sub.selections ?? []) {
        if (f.name === 'hasNextPage') pi.hasNextPage = hasNextPage;
        else if (f.name === 'endCursor') pi.endCursor = endCursor;
      }
      out.pageInfo = pi;
    } else if (sub.name === 'totalCount') out.totalCount = nodes.length;
  }
  return out;
}

function findRepoByGlobalId(id: string): Repo | null {
  const decoded = b64decode(id);
  if (decoded === null || !decoded.startsWith('Repository:')) return null;
  const dbId = parseInt(decoded.slice('Repository:'.length), 10);
  return [...repos.values()].find((r) => r.dbId === dbId) ?? null;
}
function findIssueByGlobalId(id: string): { repo: Repo; issue: Issue } | null {
  const decoded = b64decode(id);
  if (decoded === null || !decoded.startsWith('Issue:')) return null;
  const parts = decoded.split(':');
  const dbId = parseInt(parts[1], 10);
  const num = parseInt(parts[2], 10);
  const repo = [...repos.values()].find((r) => r.dbId === dbId);
  if (repo === undefined) return null;
  const issue = repo.issues.get(num);
  if (issue === undefined) return null;
  return { repo, issue };
}
function findPrByGlobalId(id: string): { repo: Repo; pr: PullRequest } | null {
  const decoded = b64decode(id);
  if (decoded === null || !decoded.startsWith('PullRequest:')) return null;
  const parts = decoded.split(':');
  const dbId = parseInt(parts[1], 10);
  const num = parseInt(parts[2], 10);
  const repo = [...repos.values()].find((r) => r.dbId === dbId);
  if (repo === undefined) return null;
  const pr = repo.prs.get(num);
  if (pr === undefined) return null;
  return { repo, pr };
}

function executeMutation(op: GqlOperation, ctx: GqlCtx): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of op.selections) {
    const key = sel.alias ?? sel.name;
    const input = (argValue(sel, 'input', ctx) ?? {}) as Record<string, unknown>;
    if (sel.name === 'createIssue') {
      const repo = typeof input.repositoryId === 'string' ? findRepoByGlobalId(input.repositoryId) : null;
      if (repo === null) {
        ctx.errors.push(gqlError('repository not found'));
        out[key] = null;
        continue;
      }
      const created = createIssueIn(repo, String(input.title ?? ''), String(input.body ?? ''), []);
      if ('error' in created) {
        ctx.errors.push(gqlError(created.error));
        out[key] = null;
        continue;
      }
      const issueSel = sel.selections?.[0];
      out[key] = {
        issue: issueSel?.selections ? resolveSelections('Issue', created, issueSel.selections, ctx) : { number: created.number, id: created.globalId },
      };
      continue;
    }
    if (sel.name === 'closeIssue') {
      const found = typeof input.issueId === 'string' ? findIssueByGlobalId(input.issueId) : null;
      if (found === null) {
        ctx.errors.push(gqlError('issue not found'));
        out[key] = null;
        continue;
      }
      found.issue.state = 'closed';
      const issueSel = sel.selections?.[0];
      out[key] = {
        issue: issueSel?.selections ? resolveSelections('Issue', found.issue, issueSel.selections, ctx) : { number: found.issue.number, id: found.issue.globalId },
      };
      continue;
    }
    if (sel.name === 'createPullRequest') {
      const repo = typeof input.repositoryId === 'string' ? findRepoByGlobalId(input.repositoryId) : null;
      if (repo === null) {
        ctx.errors.push(gqlError('repository not found'));
        out[key] = null;
        continue;
      }
      const created = createPrIn(
        repo,
        String(input.title ?? ''),
        String((input as Record<string, unknown>).body ?? ''),
        String(input.headRefName ?? ''),
        String(input.baseRefName ?? ''),
      );
      if ('error' in created) {
        ctx.errors.push(gqlError(created.error));
        out[key] = null;
        continue;
      }
      const prSel = sel.selections?.[0];
      out[key] = {
        pullRequest: prSel?.selections ? resolveSelections('PullRequest', created, prSel.selections, ctx) : { number: created.number, id: created.globalId },
      };
      continue;
    }
    if (sel.name === 'mergePullRequest') {
      const found = typeof input.pullRequestId === 'string' ? findPrByGlobalId(input.pullRequestId) : null;
      if (found === null) {
        ctx.errors.push(gqlError('pull request not found'));
        out[key] = null;
        continue;
      }
      const result = mergePr(found.repo, found.pr);
      if (typeof result === 'object') {
        ctx.errors.push(gqlError(result.error));
        out[key] = null;
        continue;
      }
      const prSel = sel.selections?.[0];
      out[key] = {
        pullRequest: prSel?.selections ? resolveSelections('PullRequest', found.pr, prSel.selections, ctx) : { number: found.pr.number, merged: true },
      };
      continue;
    }
    if (sel.name === 'addComment') {
      const found = typeof input.subjectId === 'string' ? findIssueByGlobalId(input.subjectId) : null;
      if (found === null) {
        ctx.errors.push(gqlError('subject not found'));
        out[key] = null;
        continue;
      }
      const { repo, issue } = found;
      const id = repo.nextId;
      repo.nextId += 1;
      const seq = repo.nextSeq();
      const comment: Comment = {
        id,
        globalId: repo.globalId('IssueComment', id),
        body: String(input.body ?? ''),
        seq,
        createdAt: repo.stamp(seq),
      };
      const list = repo.comments.get(issue.number) ?? [];
      list.push(comment);
      repo.comments.set(issue.number, list);
      out[key] = { commentEdge: { node: { id: comment.globalId, body: comment.body } } };
      continue;
    }
    ctx.errors.push(gqlError(`Cannot query field "${sel.name}" on type "Mutation".`));
    out[key] = null;
  }
  return out;
}

function executeOperation(op: GqlOperation, variables: Record<string, unknown>): { data: Record<string, unknown> | null; errors: Array<{ message: string }> } {
  const ctx: GqlCtx = { variables, errors: [] };
  if (op.type === 'mutation') {
    const data = executeMutation(op, ctx);
    return { data, errors: ctx.errors };
  }
  const data = resolveSelections('Query', null, op.selections, ctx);
  return { data, errors: ctx.errors };
}

async function handleGraphql(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!authed(req)) {
    sendError(res, 401, 'Bad credentials');
    return;
  }
  const parsed = await readJsonBody(req);
  if (!parsed.ok) {
    sendError(res, 400, parsed.error);
    return;
  }
  const runOne = (body: unknown): { data: Record<string, unknown> | null; errors?: Array<{ message: string }> } => {
    if (!isRecord(body) || typeof body.query !== 'string') {
      return { data: null, errors: [gqlError('query is required')] };
    }
    const variables = isRecord(body.variables) ? (body.variables as Record<string, unknown>) : {};
    let ops: GqlOperation[];
    try {
      ops = new GqlParser(body.query).parseDocument();
    } catch (err) {
      return { data: null, errors: [gqlError(err instanceof Error ? err.message : 'parse error')] };
    }
    let op = ops[0];
    if (typeof body.operationName === 'string') {
      op = ops.find((o) => o.name === body.operationName) ?? op;
    }
    if (op === undefined) return { data: null, errors: [gqlError('no operation')] };
    const result = executeOperation(op, variables);
    if (result.errors.length > 0) return { data: result.data, errors: result.errors };
    return { data: result.data };
  };
  if (Array.isArray(parsed.value)) {
    const results = parsed.value.map((b) => runOne(b));
    sendJson(res, 200, results);
    return;
  }
  const result = runOne(parsed.value);
  sendJson(res, 200, result);
}

// ---------------------------------------------------------------------------
// MCP (Model Context Protocol, streamable HTTP / JSON-RPC 2.0)
// ---------------------------------------------------------------------------

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name.' },
        description: { type: 'string', description: 'Repository description.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner.' },
        repo: { type: 'string', description: 'Repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner.' },
        repo: { type: 'string', description: 'Repository name.' },
        title: { type: 'string', description: 'Issue title.' },
        body: { type: 'string', description: 'Issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues of a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner.' },
        repo: { type: 'string', description: 'Repository name.' },
        state: { type: 'string', description: 'Issue state filter: open, closed, all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner.' },
        repo: { type: 'string', description: 'Repository name.' },
        title: { type: 'string', description: 'Pull request title.' },
        body: { type: 'string', description: 'Pull request body.' },
        head: { type: 'string', description: 'Head branch name.' },
        base: { type: 'string', description: 'Base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner.' },
        repo: { type: 'string', description: 'Repository name.' },
        pull_number: { type: 'integer', description: 'Pull request number.' },
        number: { type: 'integer', description: 'Pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpPick(args: Record<string, unknown>, names: string[]): unknown {
  for (const n of names) {
    if (args[n] !== undefined && args[n] !== null) return args[n];
  }
  return undefined;
}
function mcpOwnerRepo(args: Record<string, unknown>): { owner: string; repo: string } | null {
  let owner = mcpPick(args, ['owner', 'owner_login', 'org', 'organization', 'user', 'login', 'account', 'namespace', 'owner_name']);
  let repo = mcpPick(args, ['repo', 'repository', 'repository_name', 'repo_name', 'repo_slug', 'project', 'project_name']);
  const full = mcpPick(args, ['full_name', 'repo_full_name', 'repository_full_name', 'fullName']);
  if ((owner === undefined || repo === undefined) && typeof full === 'string' && full.includes('/')) {
    const parts = full.split('/');
    owner = owner ?? parts[0];
    repo = repo ?? parts[1];
  }
  if (typeof owner !== 'string' || typeof repo !== 'string') return null;
  return { owner, repo };
}
function mcpRepoFor(args: Record<string, unknown>): Repo | null {
  const or = mcpOwnerRepo(args);
  if (or === null) return null;
  learnViewer(or.owner);
  if (or.owner !== viewerLogin) return null;
  return repos.get(or.repo) ?? null;
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method === 'DELETE') {
    res.writeHead(200, { 'x-github-request-id': requestId() });
    res.end();
    return;
  }
  if (req.method !== 'POST') {
    sendError(res, 405, 'Method Not Allowed');
    return;
  }
  if (!authed(req)) {
    res.writeHead(401, { 'content-type': JSON_TYPE, 'x-github-request-id': requestId() });
    res.end(JSON.stringify({ message: 'Unauthorized' }));
    return;
  }
  const buf = await readBody(req);
  let rpc: unknown;
  try {
    rpc = JSON.parse(buf.toString('utf8'));
  } catch {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  if (!isRecord(rpc) || typeof rpc.method !== 'string') {
    sendJson(res, 400, { jsonrpc: '2.0', id: isRecord(rpc) ? (rpc.id ?? null) : null, error: { code: -32600, message: 'Invalid Request' } });
    return;
  }
  const id = rpc.id ?? null;
  const method = rpc.method as string;
  const params = isRecord(rpc.params) ? rpc.params : {};
  // Notification (no id): no response body.
  if (id === null && method.startsWith('notifications/')) {
    res.writeHead(202, { 'x-github-request-id': requestId() });
    res.end();
    return;
  }
  const ok = (result: unknown): void => {
    sendJson(res, 200, { jsonrpc: '2.0', id, result });
  };
  const fail = (code: number, message: string): void => {
    sendJson(res, 200, { jsonrpc: '2.0', id, error: { code, message } });
  };
  if (method === 'server/discover') {
    const serverInfo = { name: 'forge', version: '1.0.0' };
    ok({
      supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'],
      capabilities: { tools: {} },
      serverInfo,
      instructions: 'A GitHub-compatible git forge.',
      _meta: { 'io.modelcontextprotocol/serverInfo': serverInfo },
    });
    return;
  }
  if (method === 'initialize') {
    const offered = typeof (params as Record<string, unknown>).protocolVersion === 'string'
      ? (params as Record<string, unknown>).protocolVersion as string
      : '2025-11-25';
    ok({
      protocolVersion: offered,
      capabilities: { tools: {} },
      serverInfo: { name: 'forge', version: '1.0.0' },
    });
    return;
  }
  if (method === 'tools/list') {
    ok({ tools: MCP_TOOLS });
    return;
  }
  if (method === 'tools/call') {
    const name = typeof params.name === 'string' ? params.name : '';
    const args = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
    const tool = MCP_TOOLS.find((t) => t.name === name);
    if (tool === undefined) {
      fail(-32602, `unknown tool ${name}`);
      return;
    }
    const needError = (missing: string): void => {
      ok({ content: [{ type: 'text', text: JSON.stringify({ error: `Missing required argument: ${missing}` }) }], isError: true });
    };
    const resultText = (structured: unknown): void => {
      ok({ content: [{ type: 'text', text: JSON.stringify(structured) }], structuredContent: structured });
    };
    if (name === 'create_repo') {
      const repoName = mcpPick(args, ['name', 'repo', 'repository', 'repository_name', 'repo_name']);
      if (typeof repoName !== 'string' || repoName === '') {
        needError('name');
        return;
      }
      if (repos.has(repoName)) {
        needError('name');
        return;
      }
      const repo = new Repo(repoName, nextDbId, String(mcpPick(args, ['description', 'about', 'summary', 'body']) ?? ''), mcpPick(args, ['private', 'is_private']) === true);
      nextDbId += 1;
      repos.set(repoName, repo);
      resultText({ id: repo.dbId, name: repo.name, full_name: `${viewerName()}/${repo.name}`, owner: { login: viewerName() }, private: repo.isPrivate, description: repo.description, default_branch: 'main' });
      return;
    }
    if (name === 'get_repo') {
      const repo = mcpRepoFor(args);
      if (repo === null) {
        needError('owner/repo');
        return;
      }
      resultText({ id: repo.dbId, name: repo.name, full_name: `${viewerName()}/${repo.name}`, owner: { login: viewerName() }, private: repo.isPrivate, description: repo.description, default_branch: 'main' });
      return;
    }
    if (name === 'create_issue') {
      const repo = mcpRepoFor(args);
      const title = mcpPick(args, ['title', 'issue_title', 'subject']);
      if (repo === null || typeof title !== 'string') {
        needError(repo === null ? 'owner/repo' : 'title');
        return;
      }
      const created = createIssueIn(repo, title, String(mcpPick(args, ['body', 'issue_body', 'description', 'content', 'text']) ?? ''), []);
      if ('error' in created) {
        needError(created.error);
        return;
      }
      resultText({ id: created.id, number: created.number, title: created.title, body: created.body, state: created.state, full_name: `${viewerName()}/${repo.name}` });
      return;
    }
    if (name === 'list_issues') {
      const repo = mcpRepoFor(args);
      if (repo === null) {
        needError('owner/repo');
        return;
      }
      const state = String(mcpPick(args, ['state', 'status']) ?? 'open');
      let list = [...repo.issues.values()];
      if (state !== 'all') list = list.filter((i) => i.state === state);
      list.sort((a, b) => a.number - b.number);
      resultText({ issues: list.map((i) => ({ id: i.id, number: i.number, title: i.title, body: i.body, state: i.state })) });
      return;
    }
    if (name === 'create_pull_request') {
      const repo = mcpRepoFor(args);
      const title = mcpPick(args, ['title', 'pr_title', 'pull_request_title', 'subject']);
      const head = mcpPick(args, ['head', 'head_ref', 'head_branch', 'source', 'source_branch', 'from_branch', 'branch']);
      const base = mcpPick(args, ['base', 'base_ref', 'base_branch', 'target', 'into_branch']);
      if (repo === null || typeof title !== 'string' || typeof head !== 'string' || typeof base !== 'string') {
        needError('owner/repo/title/head/base');
        return;
      }
      const created = createPrIn(repo, title, String(mcpPick(args, ['body', 'description', 'content', 'text']) ?? ''), head, base);
      if ('error' in created) {
        needError(created.error);
        return;
      }
      resultText({ id: created.id, number: created.number, title: created.title, body: created.body, state: created.state, head: { ref: created.head, sha: created.headSha }, base: { ref: created.base, sha: created.baseSha } });
      return;
    }
    if (name === 'merge_pull_request') {
      const repo = mcpRepoFor(args);
      const numRaw = mcpPick(args, ['pull_number', 'pull_request_number', 'pr_number', 'number', 'issue_number', 'index']);
      const num = typeof numRaw === 'number' ? numRaw : typeof numRaw === 'string' ? parseInt(numRaw, 10) : NaN;
      if (repo === null || !Number.isInteger(num)) {
        needError('owner/repo/pull_number');
        return;
      }
      const pr = repo.prs.get(num);
      if (pr === undefined) {
        needError('pull request not found');
        return;
      }
      const result = mergePr(repo, pr);
      if (typeof result === 'object') {
        ok({ content: [{ type: 'text', text: JSON.stringify({ error: result.error }) }], isError: true });
        return;
      }
      resultText({ number: pr.number, merged: true, sha: result, state: pr.state });
      return;
    }
    fail(-32602, `unknown tool ${name}`);
    return;
  }
  fail(-32601, `method not found: ${method}`);
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const method = req.method ?? 'GET';
        const path = pathOf(req);
        if (method === 'GET' && path === '/healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }
        if (path === '/mcp') {
          await handleMcp(req, res);
          return;
        }
        if (path === '/api/graphql' && method === 'POST') {
          await handleGraphql(req, res);
          return;
        }
        if (path.startsWith('/api/v3')) {
          await handleRest(req, res);
          return;
        }
        const gitMatch = path.match(/^\/([^/]+)\/([^/]+)\.git\/(info\/refs|git-upload-pack|git-receive-pack)$/);
        if (gitMatch !== null) {
          const owner = decodeURIComponent(gitMatch[1]);
          const repoName = decodeURIComponent(gitMatch[2]);
          const action = gitMatch[3];
          if (action === 'info/refs' && method === 'GET') {
            const service = queryOf(req).get('service') ?? '';
            handleInfoRefs(req, res, owner, repoName, service);
            return;
          }
          if ((action === 'git-upload-pack' || action === 'git-receive-pack') && method === 'POST') {
            const body = await readBody(req).catch(() => Buffer.alloc(0));
            if (action === 'git-upload-pack') handleUploadPack(req, res, owner, repoName, body);
            else handleReceivePack(req, res, owner, repoName, body);
            return;
          }
          sendJson(res, 404, { message: 'Not Found' });
          return;
        }
        sendJson(res, 404, { message: 'Not Found' });
      } catch (err) {
        if (!res.headersSent) {
          sendError(res, 500, err instanceof Error ? err.message : 'internal error');
        } else {
          try {
            res.end();
          } catch {
            // ignore
          }
        }
      }
    })();
  });
}
