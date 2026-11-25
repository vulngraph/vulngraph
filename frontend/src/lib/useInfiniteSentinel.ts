import { useEffect, type RefObject } from "react";

// InfinitePaging is the slice of a TanStack useInfiniteQuery result the sentinel
// needs. Declared structurally so any paging hook (useFindings, and anything
// shaped like it) can be passed straight through.
export interface InfinitePaging {
  hasNextPage: boolean;
  isFetchingNextPage: boolean;
  fetchNextPage: () => unknown;
}

// useInfiniteSentinel auto-loads the next page when the element `ref` points at
// scrolls into view — no manual "load more" click. It was hand-rolled
// identically in MustFixView, StartHereView and Findings' InstanceView; three
// copies of an effect with a subtle dependency list is three chances to get the
// stale-closure wrong, so it lives here once.
//
// The 200px rootMargin fetches slightly before the sentinel is actually visible,
// so the next page is usually already in place by the time the user reaches it.
export function useInfiniteSentinel(
  ref: RefObject<Element | null>,
  { hasNextPage, isFetchingNextPage, fetchNextPage }: InfinitePaging,
) {
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && hasNextPage && !isFetchingNextPage) void fetchNextPage();
      },
      { rootMargin: "200px" },
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, [ref, hasNextPage, isFetchingNextPage, fetchNextPage]);
}
