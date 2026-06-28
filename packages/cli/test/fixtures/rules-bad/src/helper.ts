export function helper(req: Request): Promise<Response> {
  return fetch(req.url);
}
