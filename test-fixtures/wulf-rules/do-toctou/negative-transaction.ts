export class Counter {
  constructor(private ctx: DurableObjectState) {}

  async fetch() {
    // ok: wulf-do-toctou
    await this.ctx.storage.transaction(async (txn) => {
      const current = await txn.get<number>("count");
      await txn.put("count", (current ?? 0) + 1);
    });
    return new Response("ok");
  }
}
