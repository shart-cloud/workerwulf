export class AccountObject {
  constructor(private ctx: DurableObjectState) {}

  async deleteAccount() {
    await this.ctx.storage.deleteAlarm();
    // ok: wulf-orphaned-alarm-on-delete
    await this.ctx.storage.deleteAll();
    return new Response("deleted");
  }
}
