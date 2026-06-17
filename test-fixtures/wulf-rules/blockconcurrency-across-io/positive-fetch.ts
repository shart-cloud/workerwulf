export class Gate {
  constructor(private ctx: DurableObjectState) {}

  async fetch() {
    // ruleid: wulf-blockconcurrency-across-io
    await this.ctx.blockConcurrencyWhile(async () => {
      await fetch("https://example.com/slow");
    });
    return new Response("ok");
  }
}
