export class Gate {
  constructor(private ctx: DurableObjectState, private env: { BUCKET: R2Bucket }) {}

  async fetch() {
    // ruleid: wulf-blockconcurrency-across-io
    await this.ctx.blockConcurrencyWhile(async () => {
      await env.BUCKET.get("key");
    });
    return new Response("ok");
  }
}
