class ExampleDurableObject {
  private sql: SqlStorage;

  constructor(state: DurableObjectState) {
    this.sql = state.storage.sql;
  }

  listUsers() {
    const query = "SELECT id, username FROM users ORDER BY id";
    // ok: wulf-sql-exec-concat
    return this.sql.exec(query);
  }
}
