#!/usr/bin/env python3
"""기본 보안 정적 점검. 파일을 읽기만 하며 대상 코드 실행과 네트워크 호출을 하지 않는다. 시크릿 값은 출력하지 않는다.
Usage: scan.py <repo> [--json out.json] [--fail-on high|medium|low]
종료 코드: 0 정상, 1 --fail-on 이상 발견, 2 사용 오류.
"""
import argparse, json, os, re, subprocess, sys

SKIP_DIRS = {".git", "node_modules", "dist", "build", ".next", "out", "vendor", "__pycache__", ".venv", "venv", "target", "coverage", ".hyperframes"}
TEXT_EXT = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".rb", ".go", ".java", ".kt", ".php", ".rs", ".cs", ".sql", ".sh", ".yml", ".yaml", ".json", ".toml", ".env", ".ini", ".cfg", ".conf", ".properties", ".tf"}
MAX_SIZE = 1_000_000
RANK = {"high": 3, "medium": 2, "low": 1}

SECRETS = [
    ("AWS 액세스 키", r"\bAKIA[0-9A-Z]{16}\b"),
    ("GitHub 토큰", r"\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    ("npm 토큰", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("Anthropic 키", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    ("OpenAI 키", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}"),
    ("Slack 토큰", r"\bxox[abprs]-[A-Za-z0-9-]{20,}"),
    ("Google API 키", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("Stripe 비밀 키", r"\bsk_live_[0-9A-Za-z]{20,}"),
    ("개인 키 블록", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY"),
]
GENERIC_SECRET = re.compile(r"""(?i)\b(?:[a-z0-9_]*(?:secret|password|passwd|api_?key|auth_?token|signing_?key|private_?key))\b\s*[:=]\s*["']([^"'\s]{12,})["']""")
PLACEHOLDER = re.compile(r"(?i)example|changeme|change_me|your[_-]|xxx|placeholder|dummy|test|sample|<|\$\{|\{\{|process\.env|os\.environ|lab-")
# (id, severity, 항목, 패턴, 고칠 방법)
LINE_RULES = [
    ("F1", "high", "비밀번호에 MD5/SHA-1 사용 의심", r"(?i)(?:md5|sha1|sha-1)[^\n]{0,60}(?:password|passwd|\bpw\b|비밀번호)|(?:password|passwd|\bpw\b|비밀번호)[^\n]{0,60}(?:md5|sha1|sha-1)", "Argon2id, scrypt 또는 레거시 bcrypt로 교체"),
    ("C1", "high", "요청 값이 SQL 문자열에 직접 결합됨", r"""(?i)(?:select|insert|update|delete)\s[^\n]*(?:["'`]\s*\+\s*(?:req|request|params|query|body)\b|\$\{\s*(?:req|request|params|query|body)\b|%s["']\s*%\s*(?:request|params))""", "파라미터 바인딩 사용"),
    ("B3", "medium", "서명 검증 없는 토큰 해석 의심", r"\bjwt\.decode\s*\(|verify_signature[\"']?\s*:\s*False|algorithms?\s*[:=]\s*\[?\s*[\"']none[\"']", "verify로 서명, 만료, 알고리즘 확인"),
    ("F2", "high", "TLS 인증서 검증 비활성화", r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|verify\s*=\s*False\b|InsecureSkipVerify\s*:\s*true", "검증을 켜고 신뢰 CA를 구성"),
    ("C2", "high", "업로드를 공개 경로에 저장", r"""(?i)(?:dest|destination|upload_?(?:dir|folder|path))\s*[:=(]\s*["'`]?\.{0,2}/?(?:public|static|www|wwwroot|htdocs)\b""", "webroot 밖 저장, 서버 생성 파일명 사용"),
    ("C2", "medium", "사용자 파일명을 그대로 저장 의심", r"\.originalname\b|secure_filename\s*\(\s*\)|\.filename\s*\)\s*\.save|file\.save\([^\n]*\.filename", "UUID 등 서버 생성 파일명 사용"),
    ("B6", "high", "서비스 롤 키가 공개 변수로 노출", r"(?:NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_)[A-Z0-9_]*(?:SERVICE_ROLE|SECRET|PRIVATE)[A-Z0-9_]*", "비밀값은 서버 전용 변수로 이동"),
    ("F1", "medium", "MD5/SHA-1 사용, 비밀번호 용도인지 검토", r"""createHash\(\s*["'](?:md5|sha1)["']\s*\)|hashlib\.(?:md5|sha1)\(""", "비밀번호 용도면 Argon2id, scrypt 또는 레거시 bcrypt로 교체"),
    ("C2", "high", "요청 값이 저장 경로에 직접 쓰임", r"(?:writeFile(?:Sync)?|createWriteStream)\s*\([^\n]*(?:searchParams|req\.|request\.|params\.|query\.)", "서버 생성 파일명 사용, 경로 검증, webroot 밖 저장"),
    ("C3", "high", "업로드 경로의 파일을 실행 의심", r"""(?i)(?:import|require|exec|eval)\s*\([^\n]*upload""", "업로드 파일을 실행하는 경로 제거"),
    ("B1", "medium", "요청 ID로 조회, 권한 확인 검토 필요", r"""(?:searchParams\.get|req\.query|req\.params)[^\n]{0,80}\b\w*(?:id|Id|ID)\b|\b\w*(?:id|Id|ID)\b[^\n]{0,40}searchParams\.get""", "조회 대상과 로그인 사용자의 관계를 서버에서 확인"),
    ("B1", "medium", "요청 ID로 조회, 권한 확인 검토 필요", r"""(?:findById|findUnique|findOne|\.get|where)\s*\(\s*[^\n]{0,40}\b(?:req|request)\.(?:params|query|body)\.?\w*""", "조회 대상과 로그인 사용자의 관계를 서버에서 확인"),
]
CLIENT_DIR = re.compile(r"(^|/)(?:public|client|components|pages|app|frontend|web|src/components)(/|$)")


def walk(root):
    for d, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not x.startswith(".venv") and x != "site-packages"]
        for f in files:
            p = os.path.join(d, f)
            if os.path.islink(p):
                continue
            yield p, os.path.relpath(p, root).replace(os.sep, "/")


def read(p):
    try:
        if os.path.getsize(p) > MAX_SIZE:
            return None
        with open(p, "rb") as fh:
            b = fh.read()
        if b"\0" in b[:4096]:
            return None
        return b.decode("utf-8", "replace")
    except OSError:
        return None


def tracked(root):
    try:
        r = subprocess.run(["git", "-C", root, "ls-files"], capture_output=True, text=True, timeout=30)
        return set(r.stdout.splitlines()) if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def is_test(rel):
    return bool(re.search(r"(^|/)(tests?|__tests__|fixtures?|examples?|mocks?|docs?)(/|$)|\.(test|spec)\.|(^|/)test_[^/]+$|_test\.[a-z]+$", rel))


def is_scannable(rel):
    b = os.path.basename(rel)
    return (os.path.splitext(b)[1].lower() in TEXT_EXT or b.startswith(".env") or b in {"Dockerfile", ".npmrc"}) and not re.search(r"\.min\.(js|css)$|package-lock\.json$|pnpm-lock|yarn\.lock", b)


def scan(root):
    F, n = [], 0

    def add(id_, sev, title, rel, line, fix):
        if is_test(rel) and sev != "low":
            sev = {"high": "medium", "medium": "low"}[sev]
            title += " (테스트·문서 경로)"
        F.append({"id": id_, "severity": sev, "title": title, "file": rel, "line": line, "fix": fix, "verdict": "검토 필요"})

    files = list(walk(root))
    names = {r for _, r in files}
    git = tracked(root)
    for p, rel in files:
        if not is_scannable(rel):
            continue
        t = read(p)
        if t is None:
            continue
        n += 1
        for i, line in enumerate(t.splitlines(), 1):
            if len(line) > 2000:
                continue
            for name, pat in SECRETS:
                if re.search(pat, line):
                    add("A1", "high", f"{name} 형식의 값 발견 (값 비공개)", rel, i, "값 제거 후 침해 여부 판단, 교체 절차 진행. 이력도 확인")
            m = GENERIC_SECRET.search(line)
            if m and not PLACEHOLDER.search(m.group(0)):
                add("A1", "medium", "코드에 비밀값으로 보이는 문자열 (값 비공개)", rel, i, "환경 변수나 금고로 이동")
            for id_, sev, title, pat, fix in LINE_RULES:
                if re.search(pat, line):
                    add(id_, sev, title, rel, i, fix)
            if CLIENT_DIR.search(rel) and re.search(r"(?i)service_role|SUPABASE_SECRET", line) and not rel.startswith(("server/", "api/")) and "/api/" not in rel:
                add("B6", "high", "클라이언트 경로에서 서비스 롤 키 참조", rel, i, "서버 코드로 이동")
        if rel.endswith(".sql"):
            scan_rls(t, rel, add)
    scan_env(root, names, git, add)
    scan_npm(root, names, add)
    for p, rel in files:
        if rel.startswith(".github/workflows/") and rel.endswith((".yml", ".yaml")):
            t = read(p)
            if t:
                scan_workflow(t, rel, add)
    for rel, what in ((".claude/settings.json", "hooks"), (".gemini/settings.json", "hooks"), (".cursor/mcp.json", "command"), (".vscode/tasks.json", "folderOpen"), (".github/init.js", "")):
        if rel in names:
            t = read(os.path.join(root, rel)) or ""
            if what in t:
                add("E3", "medium", "폴더를 열 때 실행될 수 있는 설정, 내용 검토", rel, 1, "만든 사람과 명령을 확인. 모르면 제거")
    F.sort(key=lambda x: (-RANK[x["severity"]], x["file"], x["line"]))
    return F, n


def scan_rls(t, rel, add):
    tables = re.finditer(r"(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?\"?(\w+)\"?", t)
    low = t.lower()
    for m in tables:
        name = m.group(1).lower()
        if not re.search(rf'alter\s+table\s+(?:only\s+)?(?:public\.)?"?{name}"?\s+enable\s+row\s+level\s+security', low):
            add("B5", "medium", f"`{name}` 테이블에 RLS 활성화가 이 파일에 없음 (Supabase 등 사용 시)", rel, t[: m.start()].count("\n") + 1, "노출 스키마면 RLS와 정책 추가. 다른 마이그레이션도 확인")


def scan_env(root, names, git, add):
    envs = [r for r in names if re.search(r"(^|/)\.env(\.[\w-]+)?$", r) and not re.search(r"\.(example|sample|template)$", r)]
    if git is not None:
        for r in envs:
            if r in git:
                keys = re.findall(r"(?m)^\s*(?:export\s+)?([A-Za-z_][\w]*)\s*=", read(os.path.join(root, r)) or "")
                public = keys and all(re.match(r"(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_)", k) and not re.search(r"SECRET|PRIVATE|SERVICE_ROLE|TOKEN|PASSWORD", k) for k in keys)
                if public:
                    add("A2", "low", ".env 파일이 Git에 커밋됨 (공개 변수만)", r, 1, "값이 공개돼도 되는지 확인")
                else:
                    add("A2", "high", ".env 파일이 Git에 커밋됨", r, 1, "추적 제거, 키 교체 판단, 이력 확인")
    if envs or git is not None:
        gi = read(os.path.join(root, ".gitignore")) if ".gitignore" in names else ""
        if envs and not re.search(r"(?m)^\s*/?\*?\.env", gi or ""):
            add("A2", "medium", ".gitignore에 .env 규칙 없음", ".gitignore", 1, ".env* 추가")


def scan_npm(root, names, add):
    for rel in sorted(r for r in names if os.path.basename(r) == "package.json"):
        d = os.path.dirname(rel)
        try:
            pkg = json.loads(read(os.path.join(root, rel)) or "{}")
        except ValueError:
            continue
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        locks = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock")
        here_or_root = [os.path.join(d, x) if d else x for x in locks] + list(locks)
        if deps and not any(x in names for x in here_or_root):
            add("D1", "medium", "잠금 파일 없음", rel, 1, "잠금 파일을 커밋하고 CI에서 npm ci 사용")
        for k, v in deps.items():
            if v in ("*", "latest", ""):
                add("D1", "medium", f"버전 미고정 의존성 `{k}`", rel, 1, "버전 고정")
        if deps and os.path.join(d, ".npmrc") not in names and ".npmrc" not in names:
            add("D2", "low", "설치 스크립트 정책 없음 (.npmrc 없음)", rel, 1, "시험 후 ignore-scripts=true 적용, 필요한 패키지만 허용")


UNTRUSTED = re.compile(r"\$\{\{\s*github\.(?:event\.(?:issue|comment|pull_request|review|discussion|head_commit|pages)[\w.\[\]*]*|head_ref)")
AGENT = re.compile(r"(?i)uses:\s*[\w./-]*(?:claude-code|run-gemini-cli|codex|copilot|cursor|aider)[\w./-]*|\b(?:claude\s+-p|gemini\s+-p|codex\s+exec)\b")


def scan_workflow(t, rel, add):
    lines = t.splitlines()
    head = "\n".join(lines)
    if not re.search(r"(?m)^permissions\s*:", head) and not re.search(r"(?m)^\s+permissions\s*:", head):
        add("D3", "medium", "`permissions` 미지정", rel, 1, "기본 contents: read, 필요한 잡만 확대")
    prt = "pull_request_target" in head
    external = re.search(r"(?m)(^|\s|\[)(issues|issue_comment|pull_request_target|pull_request_review_comment|discussion_comment)\b", head)
    in_run = False
    for i, l in enumerate(lines, 1):
        m = re.search(r"uses:\s*([^\s#]+)@([^\s#]+)", l)
        if m and not m.group(1).startswith("./") and not re.fullmatch(r"[0-9a-f]{40}", m.group(2)):
            add("D3", "low", f"액션 SHA 미고정: {m.group(1)}", rel, i, "전체 커밋 SHA로 고정")
        if re.search(r"^\s*(?:-\s*)?run\s*:", l):
            in_run = True
        elif re.search(r"^\s*(?:-\s*)?(?:uses|name|with|env|if|id)\s*:", l):
            in_run = False
        if in_run and UNTRUSTED.search(l):
            add("D4", "high", "외부 입력이 run 스크립트에 직접 삽입됨", rel, i, "중간 환경 변수에 담아 따옴표로 참조")
        if prt and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head|github\.head_ref", l):
            add("D4", "high", "pull_request_target에서 PR 코드 체크아웃", rel, i, "신뢰할 수 없는 코드 체크아웃 금지. workflow_run 분리 검토")
        if re.search(r"\bnpm\s+(?:install|i)\b(?!.*--ignore-scripts)", l) and not re.search(r"^\s*#", l):
            add("D1", "low", "CI에서 npm install 사용", rel, i, "npm ci 사용")
        if external and AGENT.search(l):
            add("E1", "high", "외부 입력 트리거에서 AI 에이전트 실행", rel, i, "자동 실행 끄기나 작성자 제한, 비밀값·쓰기 권한 분리")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--json")
    ap.add_argument("--fail-on", choices=list(RANK))
    a = ap.parse_args()
    root = os.path.abspath(a.repo)
    if not os.path.isdir(root):
        print(f"폴더 없음: {root}", file=sys.stderr)
        return 2
    F, n = scan(root)
    cnt = {k: sum(f["severity"] == k for f in F) for k in RANK}
    print(f"검사 파일 {n}개 · high {cnt['high']} · medium {cnt['medium']} · low {cnt['low']}")
    print("발견 없음은 안전하다는 뜻이 아닙니다. 결과는 코드로 판정하세요.")
    for f in F:
        print(f"[{f['severity']}] {f['id']} {f['file']}:{f['line']} {f['title']} → {f['fix']}")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump({"root": root, "files_scanned": n, "counts": cnt, "findings": F}, fh, ensure_ascii=False, indent=1)
    if a.fail_on and any(RANK[f["severity"]] >= RANK[a.fail_on] for f in F):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
