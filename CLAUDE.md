# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build/Test/Lint Commands
- **Backend**: 
  - Run server: `uvicorn onyx.main:app --reload --port 8080`
  - Model server: `uvicorn model_server.main:app --reload --port 9000`
  - Tests: `pytest path/to/test_file.py::TestClass::test_method -v`
  - Linting: `ruff check .`, `black .`, `mypy .`
- **Frontend**:
  - Run dev server: `npm run dev`
  - Tests: `npm test`, `npm test -- path/to/test`
  - Linting: `npm run lint`, `npx prettier --write .`

## Code Style Guidelines
- **Python**: Use type annotations (mypy), black formatting (120 char limit), imports ordered with reorder-python-imports
- **TypeScript/React**: Use TypeScript types, prettier formatting
- **Imports**: Organized by reorder-python-imports (backend) and ESLint (frontend)
- **Naming**: Clear, descriptive names following common conventions (snake_case for Python, camelCase for JS/TS)
- **Error Handling**: Proper exception handling with appropriate logging
- **Documentation**: Add comments for complex logic, docstrings for public APIs
- **Testing**: Write tests for new functionality and bug fixes