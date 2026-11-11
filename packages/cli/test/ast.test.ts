import { describe, expect, it } from "vitest";

import { buildBindingMap } from "../src/ast/binding-map.js";
import { functionParamNames } from "../src/ast/handlers.js";
import { isMemberAccess, isObjectLiteralProperty, isStaticMember, PROPERTY } from "../src/ast/nodes.js";
import { locAt, parse } from "../src/ast/parse.js";
import { exprName, nodeText } from "../src/ast/patterns.js";
import { findNodes } from "../src/ast/walk.js";

describe("AST offsets", () => {
  it("are UTF-16 indices, so locations after non-ASCII text are exact", () => {
    // oxc 0.40 reported UTF-8 byte offsets: this resolved to the wrong text and column.
    const src = "// note — café 🚀\nconst x = env.KV;\n";
    const source = parse("a.ts", src);
    const [member] = findNodes(source.ast, "MemberExpression");
    expect(nodeText(source, member!.node)).toBe("env.KV");
    expect(locAt(source, member!.node.start)).toMatchObject({ line: 2, column: 11 });
  });
});

describe("ESTree node predicates", () => {
  it("treats obj.x and obj['x'] as member access, but not private fields", () => {
    const source = parse("a.ts", "class A { #k = 1; m(o: any) { return [o.a, o['b'], this.#k]; } }");
    const members = findNodes(source.ast, "MemberExpression").map((f) => f.node);
    expect(members.filter(isMemberAccess).map(exprName)).toEqual(["a", "b"]);
    expect(members.filter(isStaticMember).map(exprName)).toEqual(["a"]);
  });

  it("counts object-literal properties but not destructuring ones", () => {
    const source = parse("a.ts", "const { token } = env; const o = { token: 1 };");
    const props = findNodes(source.ast, PROPERTY).filter(({ node, ancestors }) =>
      isObjectLiteralProperty(node, ancestors[ancestors.length - 1]),
    );
    expect(props).toHaveLength(1);
    expect(props[0]!.ancestors.at(-1)?.type).toBe("ObjectExpression");
  });

  it("skips a TypeScript `this` parameter and rest params, and unwraps parameter properties", () => {
    const source = parse(
      "a.ts",
      "function f(this: Foo, req: Request, ...rest: unknown[]) {}\nclass C { constructor(private y: number, z: string) {} }",
    );
    const fns = findNodes(source.ast, ["FunctionDeclaration", "FunctionExpression"]).map((f) => f.node);
    expect(fns.map(functionParamNames)).toEqual([["req"], ["y", "z"]]);
  });

  it("finds env as the second handler param even with a `this` parameter", () => {
    const source = parse(
      "a.ts",
      "export default { async fetch(this: void, req: Request, e: Env) { return e.KV.get('k'); } };",
    );
    const map = buildBindingMap(source);
    expect([...map.envNames]).toEqual(["e"]);
    expect(map.refs.map((r) => [r.name, r.methodCall])).toEqual([["KV", "get"]]);
  });
});
