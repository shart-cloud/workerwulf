export class AccountObject {
  constructor(private ctx: DurableObjectState) {}

  async resetUserData() {
    // ruleid: wulf-incomplete-do-deletion
    this.ctx.storage.sql.exec("DROP TABLE sessions");
    return new Response("reset");
  }
}
