# Diagrams

This directory holds source `.excalidraw` JSON files + rendered PNGs. Both the source and the rendered output are committed — the `.excalidraw` is the editable truth, the `.png` is what gets embedded in docs.

## Regenerate

```bash
cd docs/diagrams
uv run render.py <file>.excalidraw
```

Source files and rendered PNGs live in this directory side-by-side.

## Editing flow

1. Open the `.excalidraw` file in [excalidraw.com](https://excalidraw.com) (no login needed) or the VS Code **Excalidraw** extension.
2. Save back to the same path.
3. Re-run the renderer (above).
4. Commit both the `.excalidraw` and the regenerated `.png` in the same commit.

## Drift enforcement

The `diagram-drift` CI job (W1c-iii) fails the build if a `.excalidraw` changed without a matching PNG update. Always regenerate before committing.

## First-time setup

```bash
cd docs/diagrams
uv sync
uv run playwright install chromium
```
