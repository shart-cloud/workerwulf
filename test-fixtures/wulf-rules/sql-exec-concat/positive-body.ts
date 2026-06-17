class ExampleDurableObject {
  private sql: SqlStorage;

  constructor(state: DurableObjectState) {
    this.sql = state.storage.sql;
  }

  async create(req: Request) {
    const body = await req.text();
    const query = `INSERT INTO notes (content) VALUES ('${body}')`;
    // ruleid: wulf-sql-exec-concat
    return this.sql.exec(query);
  }
}
