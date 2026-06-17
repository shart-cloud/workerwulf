import { defineAction } from "astro:actions";
import { z } from "astro:schema";

// Actions under test for the A-ACTION probes.
export const server = {
  // JSON/RPC action with a required input — exercises JSON parsing + zod validation.
  echo: defineAction({
    input: z.object({ message: z.string() }),
    handler: async (input) => ({ echoed: input.message }),
  }),

  // Form action — exercises multipart / urlencoded parsing.
  form: defineAction({
    accept: "form",
    input: z.object({ name: z.string() }),
    handler: async (input) => ({ hello: input.name }),
  }),

  // Nested action — exercises the dotted-path name resolution (FORBIDDEN_PATH_KEYS guard).
  nested: {
    echo: defineAction({
      input: z.object({ message: z.string() }),
      handler: async (input) => ({ echoed: input.message }),
    }),
  },
};
