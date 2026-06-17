class ExampleDurableObject {
  private sql: SqlStorage;

  constructor(state: DurableObjectState) {
    this.sql = state.storage.sql;
  }

  loadExtension(ext: string) {
    if (/['"\\]/.test(ext)) throw new Error("invalid extension name");
    // ruleid: wulf-sql-exec-dynamic-identifier
    return this.sql.exec(`SELECT load_extension('${ext}')`);
  }
}
