export class Counter {
  constructor(private ctx: DurableObjectState) {}

  async fetch() {
    // ruleid: wulf-do-toctou
    const current = await this.ctx.storage.get<number>("count");
    await fetch("https://example.com/audit");
    await this.ctx.storage.put("count", (current ?? 0) + 1);
    return new Response("ok");
  }
}
