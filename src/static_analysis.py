import re

PATTERNS = {
    "CWE-787": r"(strcpy|strcat|sprintf|gets)\s*\(",
    "CWE-798": r"(0x[0-9A-Fa-f]{2}|password\s*=\s*\")",
    "CWE-327": r"(XOR|\^=|xor_encrypt)",
    "CWE-252": r"(malloc|calloc|realloc)\s*\([^;]+\)\s*;",
    "CWE-476": r"->\s*\w+",
}

def detect(code: str) -> dict:
    findings = []
    for cwe, pattern in PATTERNS.items():
        for m in re.finditer(pattern, code):
            findings.append({"cwe": cwe, "line": code[:m.start()].count("\n") + 1})
    return {"findings": findings}