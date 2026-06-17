class ExampleDurableObject {
  private sql: SqlStorage;

  constructor(state: DurableObjectState) {
    this.sql = state.storage.sql;
  }

  findUser(username: string) {
    // ok: wulf-sql-exec-dynamic-identifier
    return this.sql.exec("SELECT * FROM users WHERE username = ?", username);
  }
}
