export class AccountObject {
  constructor(private ctx: DurableObjectState) {}

  async deleteAccount() {
    // ruleid: wulf-incomplete-do-deletion
    await this.ctx.storage.delete("profile");
    return new Response("deleted");
  }
}
