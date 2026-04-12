import { defineConfig } from "astro/config";
import mdx from "@astrojs/mdx";
import rehypeSlug from "rehype-slug";
import rehypeAutolinkHeadings from "rehype-autolink-headings";

export default defineConfig({
  site: "https://gatehouse.to",
  base: "/",
  trailingSlash: "always",
  integrations: [mdx()],
  markdown: {
    shikiConfig: {
      theme: "one-dark-pro",
      wrap: true,
    },
    rehypePlugins: [
      rehypeSlug,
      [
        rehypeAutolinkHeadings,
        {
          behavior: "append",
          properties: { className: ["heading-anchor"], ariaLabel: "Link to this heading" },
          content: { type: "text", value: "#" },
        },
      ],
    ],
  },
  build: {
    assets: "_assets",
  },
});
