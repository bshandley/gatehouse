#!/bin/sh
# Routes the image's arguments. No arguments starts the server.
#   backup | export | import | verify  -> the gatehouse CLI
#   help | --help | -h                 -> the gatehouse CLI usage
#   mcp [args]                         -> the stdio MCP server
#   anything else                      -> bun run <args> (keeps `docker run IMAGE src/index.ts` working)
set -e
case "${1:-}" in
  backup|export|import|verify|help|--help|-h) exec bun run src/cli.ts "$@" ;;
  mcp) shift; exec bun run src/mcp-stdio.ts "$@" ;;
  "") exec bun run src/index.ts ;;
  *) exec bun run "$@" ;;
esac
