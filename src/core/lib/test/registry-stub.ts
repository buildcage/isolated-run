/**
 * The fetch stub the registry reads are tested against.
 *
 * Shared because oci-registry.ts and oci-bundle.ts speak to the same registry
 * through the same client, so their tests answer the same endpoints; it lives
 * here rather than in one of them so neither test file has to import the other.
 */
import { expect, assert } from "vitest";

import { VerifyImageError } from "../provenance/errors.ts";
import type { FetchLike, FetchLikeResponse } from "../provenance/oci-registry.ts";

/** Says the stub was asked for a path it has no answer for; see expectVerifyError. */
export const UNSTUBBED = "unstubbed registry request";

export type Route = FetchLikeResponse | ((url: string) => FetchLikeResponse);
export type RegistryStub = FetchLike & { urls: string[] };

/**
 * A fetch stub answering by URL path, so a test states what each endpoint holds
 * rather than the order the calls come in. A path no key matches fails the test
 * instead of being answered by whatever response came last.
 */
export function stubRegistry(routes: Record<string, Route>): RegistryStub {
  const urls: string[] = [];
  return Object.assign(
    async (url: string) => {
      urls.push(url);
      const key = Object.keys(routes).find((k) => url.includes(k));
      if (key === undefined) throw new Error(`${UNSTUBBED}: ${url}`);
      const route = routes[key]!;
      return typeof route === "function" ? route(url) : route;
    },
    { urls },
  );
}

export function okJson(body: unknown): FetchLikeResponse {
  return okBytes(new TextEncoder().encode(JSON.stringify(body)), body);
}

/** A 200 serving `bytes` as its body, which parse to `body`. */
export function okBytes(bytes: Uint8Array, body: unknown): FetchLikeResponse {
  return {
    ok: true,
    status: 200,
    json: async () => body,
    arrayBuffer: async () => bytes.slice().buffer,
  };
}

/** A refusal with an empty JSON body, which some paths read before classifying it. */
export function failsWith(status: number): FetchLikeResponse {
  return { ok: false, status, json: async () => ({}) };
}

/** Usable as a whole stub or as one route: the request never completes. */
export function networkFailure(): never {
  throw new TypeError("fetch failed");
}

/**
 * Assert a registry call refuses with a VerifyImageError carrying `code`.
 *
 * An error raised by an unstubbed request is rejected too: it arrives wrapped as
 * a perfectly plausible TRANSIENT, which would let a stale stub pass.
 */
export async function expectVerifyError(
  call: Promise<unknown>,
  code: string,
  message?: string | RegExp,
): Promise<void> {
  try {
    await call;
  } catch (err) {
    expect(err).toBeInstanceOf(VerifyImageError);
    const failure = err as VerifyImageError;
    expect(failure.message).not.toContain(UNSTUBBED);
    expect(failure.code).toBe(code);
    if (message !== undefined) expect(failure.message).toMatch(message);
    return;
  }
  assert.fail("should have thrown");
}
