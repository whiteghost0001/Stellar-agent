/**
 * #656 — Server-Sent Events streaming for long-running job results.
 *
 * This module provides a typed SSE client for streaming job lifecycle events
 * and long-running deliverable results from the Bear dashboard API.
 *
 * The dashboard already exposes `GET /api/stream` as a general-purpose SSE
 * endpoint that emits `invalidate`, `ping`, and `hello` events. This module
 * wraps that endpoint (and any custom agent endpoint) with:
 *
 *   - Typed event decoders (so consumers get autocomplete on event payloads).
 *   - Automatic reconnection with exponential backoff.
 *   - AbortController support for graceful cancellation.
 *   - A polling fallback that degrades to regular `getJob()` calls if the
 *     server doesn't support SSE.
 *
 * ### Usage
 *
 * ```typescript
 * import { streamJobEvents, streamJobResult } from "marc-stellar-sdk";
 *
 * // Stream lifecycle events for a specific job
 * const controller = streamJobEvents({
 *   url: "http://localhost:3000/api/stream",
 *   onEvent: (event) => {
 *     console.log(event.type, event.data);
 *   },
 * });
 *
 * // Cancel the stream after 30 seconds
 * setTimeout(() => controller.abort(), 30_000);
 *
 * // Stream the result of a long-running job as it arrives
 * const result = await streamJobResult({
 *   url: "https://agent.example.com/api/jobs/42/result",
 *   onChunk: (chunk) => {
 *     process.stdout.write(chunk.data);
 *   },
 * });
 * ```
 */

import type { Job, JobStatus } from "./types.js";

// ---------------------------------------------------------------------------
// SSE event types
// ---------------------------------------------------------------------------

/**
 * A decoded SSE event emitted by the dashboard's `/api/stream` endpoint.
 */
export interface JobStreamEvent {
  /** The SSE `event:` field value (e.g. `"invalidate"`, `"ping"`, `"hello"`). */
  type: string;
  /** The parsed JSON `data:` payload, or the raw string if not JSON. */
  data: unknown;
  /** The raw SSE frame as received from the server. */
  raw: string;
}

/**
 * A decoded chunk of a long-running job result stream.
 * This mirrors the `StreamChunk` type from `marcFetch.ts` but is specialized
 * for job-result streaming.
 */
export interface JobResultChunk {
  /** Raw UTF-8 text of this chunk. */
  raw: string;
  /** The `data:` field value stripped of the prefix. */
  data: string;
  /** Parsed JSON payload when the chunk is valid JSON, `null` otherwise. */
  parsed: unknown | null;
  /** Whether this is a terminal `data: [DONE]` sentinel frame. */
  done: boolean;
}

// ---------------------------------------------------------------------------
// SSE stream client for job lifecycle events
// ---------------------------------------------------------------------------

/**
 * Options for {@link streamJobEvents}.
 */
export interface StreamJobEventsOptions {
  /** The SSE endpoint URL (e.g. `http://localhost:3000/api/stream`). */
  url: string;
  /** Optional Bearer token for authenticated SSE endpoints. */
  token?: string;
  /** Callback invoked for each decoded SSE event. */
  onEvent: (event: JobStreamEvent) => void;
  /** Callback invoked when the connection errors (before a reconnect). */
  onError?: (error: Error) => void;
  /** Callback invoked when the connection is (re)established. */
  onConnect?: () => void;
  /**
   * Whether to automatically reconnect on connection loss.
   * Default: `true`.
   */
  autoReconnect?: boolean;
  /**
   * Maximum number of reconnection attempts.
   * Default: `5`.
   */
  maxReconnects?: number;
  /**
   * Base delay (ms) before the first reconnect attempt.
   * Default: `1000`.
   */
  reconnectDelay?: number;
  /**
   * Backoff multiplier for reconnect delays.
   * Default: `2`.
   */
  reconnectBackoff?: number;
  /**
   * Optional custom fetch implementation (for testing).
   */
  fetchImpl?: typeof fetch;
}

/**
 * A handle to an active SSE job-event stream. Call `abort()` to cancel.
 */
export interface JobStreamHandle {
  /** Abort the stream and close the connection. */
  abort: () => void;
}

/**
 * Stream job lifecycle events from an SSE endpoint.
 *
 * Connects to the given `url`, decodes incoming SSE frames, and invokes
 * `onEvent` for each one. If the connection drops and `autoReconnect` is
 * enabled (default), it reconnects with exponential backoff.
 *
 * @returns A handle with an `abort()` method to cancel the stream.
 *
 * @example
 * ```typescript
 * const handle = streamJobEvents({
 *   url: "http://localhost:3000/api/stream",
 *   onEvent: (event) => {
 *     if (event.type === "invalidate") {
 *       console.log("Data invalidated, refetching...");
 *     }
 *   },
 * });
 * // Later: handle.abort();
 * ```
 */
export function streamJobEvents(opts: StreamJobEventsOptions): JobStreamHandle {
  const {
    url,
    token,
    onEvent,
    onError,
    onConnect,
    autoReconnect = true,
    maxReconnects = 5,
    reconnectDelay = 1000,
    reconnectBackoff = 2,
    fetchImpl,
  } = opts;

  const controller = new AbortController();
  let reconnectAttempts = 0;
  let stopped = false;

  const headers: Record<string, string> = {
    Accept: "text/event-stream",
    "Cache-Control": "no-cache",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  async function connect(): Promise<void> {
    if (stopped) return;

    try {
      const response = await (fetchImpl ?? fetch)(url, {
        method: "GET",
        headers,
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`SSE connection failed: ${response.status} ${response.statusText}`);
      }

      if (!response.body) {
        throw new Error("SSE connection returned no body");
      }

      reconnectAttempts = 0;
      onConnect?.();

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (!stopped) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });

        // SSE events are separated by `\n\n`
        const events = buffer.split("\n\n");
        // Keep the last (potentially incomplete) event in the buffer.
        buffer = events.pop() ?? "";

        for (const rawEvent of events) {
          const decoded = decodeSseEvent(rawEvent);
          if (decoded) {
            onEvent(decoded);
          }
        }
      }

      // Flush remaining buffer on clean close.
      if (!stopped && buffer.trim()) {
        const decoded = decodeSseEvent(buffer);
        if (decoded) onEvent(decoded);
      }
    } catch (err) {
      if (stopped || controller.signal.aborted) return;

      const error = err instanceof Error ? err : new Error(String(err));
      onError?.(error);

      if (autoReconnect && reconnectAttempts < maxReconnects) {
        reconnectAttempts += 1;
        const delay = reconnectDelay * Math.pow(reconnectBackoff, reconnectAttempts - 1);
        await new Promise((r) => setTimeout(r, delay));
        if (!stopped) {
          return connect();
        }
      }
    }
  }

  // Start the connection (async, not awaited).
  connect();

  return {
    abort: () => {
      stopped = true;
      controller.abort();
    },
  };
}

/**
 * Decode a raw SSE event block (text between `\n\n` delimiters) into a
 * {@link JobStreamEvent}.
 *
 * @internal
 */
function decodeSseEvent(raw: string): JobStreamEvent | null {
  const lines = raw.trim().split("\n");
  let type = "message";
  const dataLines: string[] = [];

  for (const line of lines) {
    if (line.startsWith(":")) continue; // SSE comment / keep-alive
    if (line.startsWith("event:")) {
      type = line.slice(6).trim();
    } else if (line.startsWith("data:")) {
      dataLines.push(line.slice(5).trimStart());
    }
  }

  if (dataLines.length === 0 && type === "message") return null;

  const dataStr = dataLines.join("\n");
  let data: unknown = dataStr;
  try {
    data = JSON.parse(dataStr);
  } catch {
    // keep as string
  }

  return { type, data, raw: raw.trim() };
}

// ---------------------------------------------------------------------------
// Job result stream (streaming deliverable output)
// ---------------------------------------------------------------------------

/**
 * Options for {@link streamJobResult}.
 */
export interface StreamJobResultOptions {
  /** URL of the streaming endpoint (e.g. `https://agent.example.com/api/jobs/42/result`). */
  url: string;
  /** Optional Bearer token for authenticated endpoints. */
  token?: string;
  /** Callback invoked for each decoded chunk of the result. */
  onChunk: (chunk: JobResultChunk) => void;
  /** Optional callback invoked when the stream errors. */
  onError?: (error: Error) => void;
  /** Optional per-request timeout in milliseconds. */
  timeoutMs?: number;
  /** Optional custom fetch implementation (for testing). */
  fetchImpl?: typeof fetch;
  /** Optional AbortSignal for caller-initiated cancellation. */
  signal?: AbortSignal;
}

/**
 * Stream a long-running job result from an SSE or chunked HTTP endpoint.
 *
 * Unlike {@link streamJobEvents} (which stays open indefinitely), this
 * function resolves once the stream terminates (either via `data: [DONE]`
 * or a natural end-of-stream). The `onChunk` callback receives each decoded
 * chunk as it arrives, enabling real-time display of agent work output.
 *
 * @returns The accumulated result text once the stream completes.
 *
 * @example
 * ```typescript
 * const result = await streamJobResult({
 *   url: "https://agent.example.com/api/jobs/42/result",
 *   onChunk: (chunk) => {
 *     if (chunk.parsed) {
 *       console.log("Delta:", chunk.parsed);
 *     } else {
 *       process.stdout.write(chunk.data);
 *     }
 *   },
 * });
 * console.log("Full result:", result);
 * ```
 */
export async function streamJobResult(
  opts: StreamJobResultOptions,
): Promise<string> {
  const { url, token, onChunk, onError, timeoutMs, fetchImpl, signal } = opts;

  const headers: Record<string, string> = {
    Accept: "text/event-stream, application/octet-stream, */*",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const controller = new AbortController();
  const timeoutHandle =
    typeof timeoutMs === "number" && timeoutMs > 0
      ? setTimeout(() => controller.abort(), timeoutMs)
      : undefined;

  // Link the external signal to our internal controller.
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener("abort", () => controller.abort(), { once: true });
  }

  try {
    const response = await (fetchImpl ?? fetch)(url, {
      method: "GET",
      headers,
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`Job result stream failed: ${response.status} ${response.statusText}`);
    }

    if (!response.body) {
      return "";
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let fullText = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });

      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";

      for (const line of lines) {
        const chunk = decodeResultLine(line.trimEnd());
        if (!chunk) continue;

        onChunk(chunk);
        if (!chunk.done) {
          fullText += chunk.data;
        }

        if (chunk.done) {
          return fullText;
        }
      }
    }

    // Flush remaining buffer.
    if (buffer.trim()) {
      const chunk = decodeResultLine(buffer.trim());
      if (chunk) {
        onChunk(chunk);
        if (!chunk.done) {
          fullText += chunk.data;
        }
      }
    }

    return fullText;
  } catch (err) {
    const error = err instanceof Error ? err : new Error(String(err));
    if (error.name === "AbortError") {
      // Graceful cancellation — return what we have.
      return "";
    }
    onError?.(error);
    throw error;
  } finally {
    if (timeoutHandle) clearTimeout(timeoutHandle);
  }
}

/**
 * Decode a raw line from a job-result stream into a {@link JobResultChunk}.
 *
 * @internal
 */
function decodeResultLine(line: string): JobResultChunk | null {
  if (line === "" || line.startsWith(":")) return null;

  const isSSE = line.startsWith("data:");
  const data = isSSE ? line.slice(5).trimStart() : line;

  const done = data === "[DONE]";
  let parsed: unknown | null = null;
  if (!done) {
    try {
      parsed = JSON.parse(data);
    } catch {
      parsed = null;
    }
  }

  return { raw: line, data, parsed, done };
}

// ---------------------------------------------------------------------------
// Polling fallback for environments without SSE support
// ---------------------------------------------------------------------------

/**
 * Options for {@link pollJobUntilTerminal}.
 */
export interface PollJobOptions {
  /** A function that returns the current job state by ID. */
  getJob: (jobId: bigint) => Promise<Job | null>;
  /** The job ID to poll. */
  jobId: bigint;
  /**
   * Callback invoked on each poll iteration with the current job state.
   * Return `false` to stop polling early.
   */
  onUpdate?: (job: Job) => boolean | void;
  /** Polling interval in milliseconds. Default: `2000` (2s). */
  intervalMs?: number;
  /** Maximum polling time in milliseconds before giving up. Default: `300_000` (5 min). */
  timeoutMs?: number;
  /** Optional AbortSignal for caller-initiated cancellation. */
  signal?: AbortSignal;
}

/**
 * Poll a job until it reaches a terminal state (Completed or Cancelled).
 *
 * This is a fallback for environments that don't support SSE (e.g. serverless
 * functions) and provides the same "wait for job result" semantics as
 * {@link streamJobResult}.
 *
 * @returns The final job state, or throws on timeout.
 *
 * @example
 * ```typescript
 * const finalJob = await pollJobUntilTerminal({
 *   getJob: (id) => commerce.getJob(id),
 *   jobId: 42n,
 *   onUpdate: (job) => console.log("Status:", job.status),
 * });
 * console.log("Final:", finalJob.status);
 * ```
 */
export async function pollJobUntilTerminal(opts: PollJobOptions): Promise<Job> {
  const { getJob, jobId, onUpdate, intervalMs = 2000, timeoutMs = 300_000, signal } = opts;

  const startTime = Date.now();

  while (true) {
    if (signal?.aborted) {
      throw new Error("Polling aborted by caller");
    }

    if (Date.now() - startTime >= timeoutMs) {
      throw new Error(`Polling timed out after ${timeoutMs}ms for job ${jobId}`);
    }

    const job = await getJob(jobId);
    if (!job) {
      throw new Error(`Job ${jobId} not found`);
    }

    const shouldContinue = onUpdate?.(job);
    if (shouldContinue === false) {
      return job;
    }

    if (
      job.status === ("Completed" as JobStatus) ||
      job.status === ("Cancelled" as JobStatus)
    ) {
      return job;
    }

    await new Promise((r) => setTimeout(r, intervalMs));
  }
}
