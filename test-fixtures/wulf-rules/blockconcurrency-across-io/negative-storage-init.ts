export class Gate {
  constructor(private ctx: DurableObjectState) {}

  async fetch() {
    // ok: wulf-blockconcurrency-across-io
    await this.ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS items(id TEXT)");
    });
    return new Response("ok");
  }
}
