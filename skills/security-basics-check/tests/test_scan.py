#!/usr/bin/env python3
"""가짜 저장소로 탐지·오탐·값 비공개를 확인한다. 테스트 값은 실행 중에 조립하며 실제 키가 아니다."""
import json, os, subprocess, sys, tempfile
SCAN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "scan.py")
FAKE_GH = "gh" + "p_" + "a1B2" * 9
FAKE_LONG = "Zq9" + "xY7wV5uT3sR1"
BAD = {
 "server/a.js": f'const t="{FAKE_GH}";\nconst password_hash=md5(password);\ndb.query("SELECT * FROM u WHERE id=" + req.params.id);\nconst x=jwt.decode(t);\nconst a={{rejectUnauthorized:false}};\nconst up=multer({{dest:"public/uploads"}});\nname=f.originalname;\nconst u=await User.findById(req.params.id);\nconst api_key="{FAKE_LONG}";\n',
 ".env": "X=1\n", "web/.env.local": "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=1\n",
 "db/1.sql": "create table public.members(id int);\n",
 "package.json": '{"dependencies":{"a":"*"}}',
 ".claude/settings.json": '{"hooks":{}}',
 ".github/workflows/x.yml": "on: [issues, pull_request_target]\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: echo ${{ github.event.issue.title }}\n      - run: npm install\n      - uses: anthropics/claude-code-action@v1\n",
}
GOOD = {
 "server/a.js": 'const key=process.env.API_KEY;\ndb.query("SELECT * FROM u WHERE id=$1",[id]);\njwt.verify(t,key,{algorithms:["HS256"]});\nconst password_example="your-password-here";\n',
 "db/1.sql": "create table public.members(id int);\nalter table public.members enable row level security;\n",
 "package.json": '{"dependencies":{"a":"1.0.0"}}', "package-lock.json": "{}", ".npmrc": "ignore-scripts=true\n", ".gitignore": ".env*\n",
 ".github/workflows/x.yml": "on: [pull_request]\npermissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@" + "a"*40 + "\n      - run: npm ci\n",
}
def run(files):
    with tempfile.TemporaryDirectory() as d:
        for k, v in files.items():
            p = os.path.join(d, k); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w").write(v)
        subprocess.run(["git", "init", "-q", d]); subprocess.run(["git", "-C", d, "add", "-A", "-f"])
        o = os.path.join(d, "..", os.path.basename(d) + ".json")
        r = subprocess.run([sys.executable, SCAN, d, "--json", o], capture_output=True, text=True)
        j = json.load(open(o)); raw = open(o).read(); os.remove(o)
        return j["findings"], r.stdout + raw
bad, out = run(BAD); ids = {f["id"] for f in bad}
need = {"A1","A2","B1","B3","B5","B6","C1","C2","D1","D2","D3","D4","E1","E3","F1","F2"}
assert need <= ids, f"누락: {need-ids}"
assert FAKE_GH not in out and FAKE_LONG not in out, "시크릿 값 출력됨"
good, _ = run(GOOD)
assert not good, f"오탐: {good}"
pub, _ = run({".env.production": "EXPO_PUBLIC_API=x\n", ".gitignore": ".env\n"})
assert [f["severity"] for f in pub] == ["low"], pub
venv, _ = run({".venv-x/lib/a.py": f'k="{FAKE_GH}"\n', "s/test_a.py": "-----BEGIN " + "PRIVATE KEY\n"})
assert [f["severity"] for f in venv] == ["medium"] and venv[0]["file"] == "s/test_a.py", venv
print(f"ok: 탐지 {len(bad)}건, 규칙 {len(need)}종, 값 비공개, 정상 저장소 오탐 0")
