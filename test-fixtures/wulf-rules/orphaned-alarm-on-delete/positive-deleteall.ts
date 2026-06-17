export class AccountObject {
  constructor(private ctx: DurableObjectState) {}

  async deleteAccount() {
    // ruleid: wulf-orphaned-alarm-on-delete
    await this.ctx.storage.deleteAll();
    return new Response("deleted");
  }
}
