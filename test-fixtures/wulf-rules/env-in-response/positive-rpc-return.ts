export class RpcEntrypoint {
  constructor(private env: Record<string, unknown>) {}

  expose() {
    // ruleid: wulf-env-in-response
    return { ...this.env };
  }
}
