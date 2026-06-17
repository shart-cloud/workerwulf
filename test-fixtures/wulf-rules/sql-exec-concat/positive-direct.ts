class ExampleDurableObject {
  private sql: SqlStorage;

  constructor(state: DurableObjectState) {
    this.sql = state.storage.sql;
  }

  findUser(input: string) {
    // ruleid: wulf-sql-exec-concat
    return this.sql.exec(`SELECT * FROM users WHERE username = '${input}'`);
  }
}
