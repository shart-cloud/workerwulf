class ExampleDurableObject {
  private sql: SqlStorage;

  constructor(state: DurableObjectState) {
    this.sql = state.storage.sql;
  }

  findUser(input: string) {
    const query = `SELECT * FROM users WHERE username = '${input}'`;
    // ruleid: wulf-sql-exec-concat
    return this.sql.exec(query);
  }
}
