// The integration's content backend, as tests need it: parts and submissions by key (D-25).
export class ContentStore {
  readonly #parts = new Map<string, Uint8Array>();
  readonly #records = new Map<string, unknown>();

  put(resource: string, index: number, bytes: Uint8Array): void {
    this.#parts.set(`${resource}#${index}`, bytes.slice());
  }

  get(resource: string, index: number): Uint8Array {
    const part = this.#parts.get(`${resource}#${index}`);
    if (!part) throw new Error(`no part ${resource}#${index}`);
    return part.slice();
  }

  /** A fetcher, to check the library calls it only when it needs the bytes. */
  fetcher(resource: string, index: number, calls?: string[]): () => Promise<Uint8Array> {
    return async () => {
      calls?.push(`${resource}#${index}`);
      return this.get(resource, index);
    };
  }

  putRecord(id: string, record: unknown): void {
    this.#records.set(id, structuredClone(record));
  }

  record(id: string): unknown {
    return structuredClone(this.#records.get(id));
  }

  /** Everything stored, for scans (SP-01). */
  all(): { parts: Uint8Array[]; records: unknown[] } {
    return { parts: [...this.#parts.values()], records: [...this.#records.values()] };
  }
}

const text = new TextEncoder();

/** Encrypts `contents` as a draft's parts, stores them under `resource`, and returns the draft. */
export function addParts<D extends { addPart(content: Uint8Array, options?: { meta?: Uint8Array }): Uint8Array }>(
  draft: D,
  content: ContentStore,
  resource: string,
  contents: readonly (string | Uint8Array | { content: string | Uint8Array; meta?: string })[],
): D {
  contents.forEach((value, index) => {
    const part = typeof value === "object" && !(value instanceof Uint8Array) ? value : { content: value };
    const bytes = typeof part.content === "string" ? text.encode(part.content) : part.content;
    const meta = "meta" in part && part.meta !== undefined ? text.encode(part.meta) : undefined;
    content.put(resource, index, draft.addPart(bytes, meta ? { meta } : {}));
  });
  return draft;
}

export const read = (bytes: Uint8Array) => new TextDecoder().decode(bytes);
