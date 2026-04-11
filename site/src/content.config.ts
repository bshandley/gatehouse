import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";

const docs = defineCollection({
  loader: glob({ pattern: "**/*.{md,mdx}", base: "./src/content/docs" }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    sidebar_order: z.number(),
    sidebar_group: z.enum([
      "GETTING STARTED",
      "CORE CONCEPTS",
      "USING GATEHOUSE",
      "REFERENCE",
    ]),
  }),
});

export const collections = { docs };
