# security-basics-check

**"보안 점검해 줘" 한 줄로 내 저장소의 기본 보안 실수를 찾는 Agent Skill.** 공개된 사고와 표준에서 체크리스트 34개를 만들고, 항목마다 출처와 근거 수준을 달았습니다.

[English](#english)

## 어떻게 동작하나

1. **자동 검사:** `scan.py`가 시크릿, SQL 조합, 약한 해시, 업로드, Supabase RLS, npm, GitHub Actions, AI 에이전트 설정을 찾습니다. Python 표준 라이브러리만 씁니다.
2. **코드 판정:** 에이전트가 후보를 코드로 읽어 문제 확인, 오탐, 판단 불가로 가립니다.
3. **체크리스트:** 34개 항목을 전부 판정하고, 코드로 알 수 없는 운영 항목은 사용자 확인으로 넘깁니다.

읽기 전용입니다. 대상 코드를 실행하거나 수정하지 않고, 네트워크 요청도 보내지 않으며, 시크릿 값을 보고서에 옮기지 않습니다.

## 설치

```sh
# skills CLI (Claude Code, Codex 등 Agent Skills 지원 에이전트)
npx skills add MUSE-CODE-SPACE/security-basics-check

# Claude Code 플러그인
/plugin marketplace add MUSE-CODE-SPACE/security-basics-check
/plugin install security-basics-check@muse-security-skills
```

스캐너만 쓸 수도 있습니다.

```sh
python3 skills/security-basics-check/scripts/scan.py <repo>
```

## 시험 결과

`examples/vulnerable-demo`는 일부러 구멍을 낸 19줄짜리 앱입니다(127.0.0.1, 가짜 데이터).

| 단계 | 결과 |
|---|---|
| 자동 검사만 | 5건, 전부 실제 문제 |
| 스킬 전체 흐름 (Claude, 1회) | 체크리스트 위반 10건 + 기타 2건 |
| 소요 시간 | 약 90초 |

실제 저장소 8개에서는 첫 버전의 키 유출 후보 6건과 `.env` 후보 1건이 모두 오탐이었고, 규칙을 고쳤습니다. 지금도 예제 코드나 해시 용도 등에서 후보가 나오므로 코드 판정 단계가 필요합니다.

## 한계

- 작은 앱 한 개와 저장소 몇 개로 시험했습니다. 탐지율 수치로 일반화할 수 없습니다.
- 정적 점검이라 런타임 동작과 배포 환경은 보지 못합니다. 커밋 이력은 에이전트가 Git으로 확인합니다.
- "발견 없음"은 안전하다는 뜻이 아닙니다. 침투 테스트, 보안 인증, 법률 자문을 대신하지 않습니다.
- 권한이 있는 자기 코드에만 쓰세요.

## 근거

체크리스트와 출처는 [`checklist.md`](skills/security-basics-check/references/checklist.md)에 있습니다. OWASP Top 10:2025, OWASP Cheat Sheet, GitHub·npm·Supabase 공식 문서, Vercel 공지, 개인정보보호위원회 판단 보도를 참고했습니다. 규제 판단은 불복 소송 중일 수 있어 확정 사실로 쓰지 않습니다.

## English

An Agent Skill that checks your own repo for basic security mistakes. It runs a read-only stdlib scanner, has the agent judge each hit in code, then walks a 34-item checklist where every item carries a source and an evidence level. It never runs target code, modifies files, sends network requests, or copies secret values into reports. It is not a penetration test, certification, or legal advice, and "nothing found" does not mean safe.

```sh
npx skills add MUSE-CODE-SPACE/security-basics-check
```

## License

MIT
