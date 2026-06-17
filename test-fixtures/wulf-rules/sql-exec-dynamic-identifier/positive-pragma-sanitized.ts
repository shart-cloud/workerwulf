class ExampleDurableObject {
  private sql: SqlStorage;

  constructor(state: DurableObjectState) {
    this.sql = state.storage.sql;
  }

  pragmaList(pragma: string) {
    const safe = pragma.replace(/[^a-zA-Z0-9_]/g, "");
    // ruleid: wulf-sql-exec-dynamic-identifier
    return this.sql.exec(`PRAGMA ${safe}`);
  }
}
