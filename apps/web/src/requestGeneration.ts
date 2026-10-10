export class StaleRequestError extends Error {
  constructor() {
    super("request is obsolete");
    this.name = "StaleRequestError";
  }
}

/** Invalidate outstanding work when its owning session or dialog changes. */
export class RequestGeneration {
  private generation = 0;

  invalidate() {
    this.generation += 1;
  }

  capture() {
    const generation = this.generation;
    return () => {
      if (generation !== this.generation) throw new StaleRequestError();
    };
  }

  async run<T>(work: (assertCurrent: () => void) => Promise<T>): Promise<T> {
    const assertCurrent = this.capture();
    try {
      const result = await work(assertCurrent);
      assertCurrent();
      return result;
    } catch (error) {
      // An obsolete failure is no longer an error for the active session.
      assertCurrent();
      throw error;
    }
  }
}
