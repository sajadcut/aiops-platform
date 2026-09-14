from pathlib import Path

path = Path(__file__).with_name("finalize_cognia_primary_rag.py")
source = path.read_text(encoding="utf-8")
old = '    "    async def health_check(\\n",\n'
new = '    "    async def health_check(self) -> bool:\\n",\n'
if old not in source:
    raise RuntimeError("finalizer health_check marker pattern not found")
source = source.replace(old, new, 1)
exec(compile(source, str(path), "exec"), {"__file__": str(path), "__name__": "__main__"})
