class ExampleDurableObject {
  private sql: SqlStorage;

  constructor(state: DurableObjectState) {
    this.sql = state.storage.sql;
  }

  find(req: Request) {
    const id = new URL(req.url).searchParams.get("id") ?? "";
    // ruleid: wulf-sql-exec-concat
    return this.sql.exec(`SELECT * FROM users WHERE id = ${id}`);
  }
}
