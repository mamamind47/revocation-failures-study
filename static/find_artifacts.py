"""Step 1: discover 'artifact' models = persisted structs that link a user to a protected object."""
import re, sys, pathlib
root = pathlib.Path(sys.argv[1])
struct_re = re.compile(r'type (\w+) struct \{(.*?)\n\}', re.S)
regs = set(re.findall(r'db\.RegisterModel\(new\((\w+)\)', "\n".join(p.read_text(errors="ignore") for p in root.glob("models/**/*.go"))))
out = []
for p in root.glob("models/**/*.go"):
    if p.name.endswith("_test.go"): continue
    for name, body in struct_re.findall(p.read_text(errors="ignore")):
        if name not in regs: continue
        fields = set(re.findall(r'^\s*(\w+)\s', body, re.M))
        user = {"UserID", "UID", "PosterID", "DoerID", "OwnerID"} & fields
        obj = {"RepoID", "IssueID"} & fields
        if user and obj:
            out.append((str(p.relative_to(root)), name, sorted(user), sorted(obj)))
for r in sorted(out): print(*r, sep="\t")
