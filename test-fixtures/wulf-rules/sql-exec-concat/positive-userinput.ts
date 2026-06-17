class ExampleDurableObject {
  private sql: SqlStorage;

  constructor(state: DurableObjectState) {
    this.sql = state.storage.sql;
  }

  findUser(userInput: string) {
    const query = "SELECT * FROM users WHERE username = '" + userInput + "'";
    // ruleid: wulf-sql-exec-concat
    return this.sql.exec(query);
  }
}
