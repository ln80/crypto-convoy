import type { Clock } from "../ports.js";

/** A clock that only moves when told to. */
export function fixedClock(start = 1_700_000_000): Clock & { advance(seconds: number): void } {
  let now = start;
  return {
    now: () => now,
    advance: (seconds) => {
      now += seconds;
    },
  };
}
