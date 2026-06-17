export class AccountObject {
  constructor(private ctx: DurableObjectState) {}

  async deleteAccount() {
    // ok: wulf-incomplete-do-deletion
    await this.ctx.storage.deleteAll();
    return new Response("deleted");
  }
}
