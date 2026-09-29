"""revcov: a crude static probe for revocation coverage in a Go web app (Gitea prototype).

Step 1  artifacts: registered models linking a user field to a protected object (RepoID/IssueID).
Step 2  CL matrix: for each revocation entry point, which artifact types get cleaned up
        (transitively, depth <= DEPTH). Flags types cleaned by one member of a revocation
        group but not by another member of the same group.
Step 3  RC check: API/web handlers that (transitively) query an artifact type by user and
        never reach an access-check call. Flags them as read paths that may leak after revocation.

Source-only: nothing is built or run. Regex-level, so expect noise; this is a feasibility probe.
"""
import re, sys, json, pathlib
from collections import defaultdict

DEPTH = 3
USER_FIELDS = {"UserID", "UID", "PosterID", "DoerID"}
OBJ_FIELDS = {"RepoID", "IssueID"}
ACL_TABLES = {"Access", "Collaboration"}  # these are the grant itself
# Revocation entry points grouped by kind (per-app configuration)
REVOCATION_GROUPS = {
    "visibility->private": ["MakeRepoPrivate", "updateRepository"],
    "member removal": ["DeleteCollaboration", "removeTeamMember"],
}
ACCESS_TOKENS = re.compile(
    r"AccessibleRepositoryCondition|AccessibleRepoIDsQuery|GetUserRepoPermission|GetIndividualUserRepoPermission"
    r"|HasAnyUnitAccess|CheckRepoUnitUser|CanReadIssuesOrPulls|CanRead\(|HasAccess\(|AccessLevel\(|CanAccessRepo|"
    r"HasAnyUnitAccessOrPublicAccess|repoAssignment|reqRepoReader|CanWriteIssuesOrPulls")

# an access check whose result actually drops items, or an access condition inside the query
ROUTE_FILES = ["routers/api/v1/api.go", "routers/web/web.go"]  # per-app configuration
GATE_CONTINUE = re.compile(r"if\s+!?[\w.]*\.(Can\w+|Has\w+)\([^)]*\)\s*\{\s*continue", re.S)
GATE_QUERY = re.compile(r"AccessibleRepositoryCondition|AccessibleRepoIDsQuery|\bActor:\s")


def load(root):
    funcs = defaultdict(list)  # name -> [(file, body)]
    recvs = defaultdict(set)
    fre = re.compile(r"^func (?:\(\s*\w*\s*\*?(\w+)\) )?(\w+)\(.*?(?=^func |\Z)", re.S | re.M)
    for p in root.rglob("*.go"):
        s = str(p.relative_to(root))
        if s.endswith("_test.go") or "/migrations/" in s or s.startswith(("tests/", "contrib/", "build/")):
            continue
        txt = p.read_text(errors="ignore")
        for m in fre.finditer(txt):
            funcs[m.group(2)].append((s, m.group(0)))
            if m.group(1):  # also index methods as Recv.Method so options structs can be followed
                funcs[f"{m.group(1)}.{m.group(2)}"].append((s, m.group(0)))
                recvs[m.group(2)].add(m.group(1))
    # a bare method name shared by several receivers (ToConds, LoadAttributes, ...) would merge
    # unrelated bodies; keep only the Recv.Method entries for those
    for name, rs in recvs.items():
        if len(rs) > 1:
            funcs.pop(name, None)
    return funcs


def artifacts(root):
    txt = "\n".join(p.read_text(errors="ignore") for p in root.glob("models/**/*.go") if "migrations" not in str(p))
    regs = set(re.findall(r"db\.RegisterModel\(new\((\w+)\)", txt))
    out = {}
    for name, body in re.findall(r"type (\w+) struct \{(.*?)\n\}", txt, re.S):
        if name not in regs or name in ACL_TABLES:
            continue
        fields = set(re.findall(r"^\s*(\w+)\s", body, re.M))
        if fields & USER_FIELDS and fields & OBJ_FIELDS:
            out[name] = sorted(fields & USER_FIELDS)
    return out


def callees(body, funcs):
    out = {c for c in re.findall(r"\b(\w+)\(", body) if c in funcs}
    # interface dispatch: building an options struct implies its ToConds/ToJoins run inside db.Find
    for typ in set(re.findall(r"\b(\w+Options)\{", body)):
        for meth in ("ToConds", "ToJoins"):
            if f"{typ}.{meth}" in funcs:
                out.add(f"{typ}.{meth}")
    return out


def closure(name, funcs, depth=DEPTH):
    seen, frontier = {name}, {name}
    for _ in range(depth):
        nxt = set()
        for f in frontier:
            for _, b in funcs.get(f, []):
                nxt |= callees(b, funcs) - seen
        seen |= nxt
        frontier = nxt
    return seen


def bodies(names, funcs):
    return "\n".join(b for n in names for _, b in funcs.get(n, []))


def cleans(text, t):
    pats = [rf"(Clear|Remove|Delete|Reconsider|Unwatch)\w*{t}", rf"Delete\(&[\w.]*\b{t}\{{", rf"Delete\(new\([\w.]*\b{t}\)"]
    if t == "Watch":
        pats.append(r"WatchRepo\([^)]*,\s*false\)")
    return any(re.search(p, text) for p in pats)


def main(root):
    root = pathlib.Path(root)
    funcs = load(root)
    arts = artifacts(root)
    report = {"artifacts": arts, "cl_matrix": {}, "cl_flags": [], "rc_flags": []}

    # Step 2
    for g, members in REVOCATION_GROUPS.items():
        present = [m for m in members if m in funcs]
        row = {}
        for m in present:
            txt = bodies(closure(m, funcs), funcs)
            row[m] = sorted(t for t in arts if cleans(txt, t))
        report["cl_matrix"][g] = row
        allc = set().union(*row.values()) if row else set()
        for m in present:
            for t in sorted(allc - set(row[m])):
                report["cl_flags"].append({"group": g, "entry": m, "missing_cleanup": t,
                                           "cleaned_by": [o for o in present if t in row[o]]})

    # Step 3: model-level query functions per artifact (reference type + user filter)
    queriers = defaultdict(set)
    for name, defs in funcs.items():
        for f, b in defs:
            if not f.startswith(("models/", "services/")):
                continue
            for t in arts:
                table = re.sub(r"(?<!^)(?=[A-Z])", "_", t).lower()
                typed = re.search(rf"(&|new\(|\[\]\*?|\()[\w.]*\b{t}\b[{{)]", b)
                named = re.search(rf"[\"`]{table}[\"`.]", b)
                if (typed or named) and re.search(
                        r'(?i)user_?id|\buid\b|poster_?id', b) and not cleans(b, t):
                    queriers[t].add(name)
    # read handlers = functions registered on GET routes
    routes = "\n".join((root / f).read_text(errors="ignore") for f in ROUTE_FILES if (root / f).exists())
    read_handlers = set()
    for m in re.finditer(r'\.Get\(("[^"]*",\s*)?([^\n]*)\)', routes):
        for h in re.findall(r"\b(?:\w+\.)?(\w+)\s*(?:,|$)", m.group(2)):
            if h in funcs and h[0].isupper():
                read_handlers.add(h)
    all_q = set().union(*queriers.values()) if queriers else set()
    for name in sorted(read_handlers):
        cl = closure(name, funcs)
        hit = {t for t, qs in queriers.items() if cl & qs}
        if not hit:
            continue
        # where a filter must live: the handler, its direct helpers, the artifact queriers it reaches,
        # and converters it reaches; never the permission library itself
        scope = {name} | callees(bodies([name], funcs), funcs) | (cl & all_q) | \
            {n for n in cl if any(f.startswith("services/convert/") for f, _ in funcs[n])}
        txt = "\n".join(b for n in scope for f, b in funcs[n] if not f.startswith("models/perm/"))
        if not (GATE_CONTINUE.search(txt) or GATE_QUERY.search(txt)):
            report["rc_flags"].append({"handler": name, "file": funcs[name][0][0], "artifacts": sorted(hit)})
    return report


if __name__ == "__main__":
    r = main(sys.argv[1])
    json.dump(r, open(sys.argv[2], "w"), indent=1)
    print("artifacts:", ", ".join(r["artifacts"]))
    print("\nCL matrix:")
    for g, row in r["cl_matrix"].items():
        for m, ts in row.items():
            print(f"  [{g}] {m}: {ts}")
    print("\nCL flags:")
    for x in r["cl_flags"]:
        print("  ", x)
    print(f"\nRC flags ({len(r['rc_flags'])}):")
    for x in r["rc_flags"]:
        print("  ", x["file"], x["handler"], x["artifacts"])
