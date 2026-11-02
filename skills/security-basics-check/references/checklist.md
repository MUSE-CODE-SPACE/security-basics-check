# 기본 보안 체크리스트

최종 확인: 2026-11-02. 근거 수준: **표준**(공식 표준·문서) · **공식 사고**(당사자 공지) · **규제 판단**(규제기관 판단 보도, 불복 가능) · **보도·분석**(2차 자료).
자동 = `scan.py`가 일부만 탐지하므로 코드도 확인, 수동 = 코드·설정 확인, 운영 = 코드로 알 수 없어 사용자 확인.

## A. 키와 시크릿
| ID | 점검 | 방식 | 근거 |
|---|---|---|---|
| A1 | 소스, 이력, 설정 파일에 키가 없다 | 자동 | OWASP A04, A02 · 표준 |
| A2 | `.env`가 커밋되지 않고 `.gitignore`에 있다 | 자동 | 표준 |
| A3 | 서명키를 금고에 두고 평문 열람을 제한한다 | 수동 | 개인정보위 판단 사례 ¹ · 규제 판단(소송 중) |
| A4 | 퇴사·권한 변경 시 접근 가능했던 키를 교체한다 | 운영 | 위와 같음 ¹ |
| A5 | 프론트 공개 변수(`NEXT_PUBLIC_`, `VITE_`)에 비밀값이 없다 | 자동 | Supabase 문서 ⁵ · 표준 |
| A6 | 호스팅의 민감 값은 읽기 불가 옵션을 쓴다 | 운영 | Vercel 공지 ⁶ · 공식 사고 |
| A7 | 타사 AI·SaaS의 OAuth 권한을 검토하고 "전체 허용"을 막는다, MFA 사용 | 운영 | Vercel 공지 ⁶ · 공식 사고 |

## B. 인증과 권한
| ID | 점검 | 방식 | 근거 |
|---|---|---|---|
| B1 | 요청한 리소스와 로그인 사용자의 관계를 서버에서 매번 확인한다 | 자동+수동 | OWASP A01 · 결정문 분석 ³ |
| B2 | 비밀번호 찾기, 관리자 페이지에 인증과 권한 확인이 있다 | 수동 | 결정문 분석 ³ |
| B3 | 토큰 검증 시 서명, 만료, 알고리즘을 확인한다. `decode`만 쓰지 않는다 | 자동 | OWASP A07 · 표준 |
| B4 | 존재하지 않는 회원의 토큰을 거부한다 | 수동 | 개인정보위 판단 사례 ¹ |
| B5 | 노출 스키마의 모든 테이블에 RLS를 켜고 불필요한 grant를 회수한다 | 자동+수동 | Supabase 문서 ⁵ · CVE-2025-48757 사례 |
| B6 | Supabase secret/service role 키는 서버에서만 쓴다 | 자동 | Supabase 문서 ⁵ |

## C. 입력과 파일
| ID | 점검 | 방식 | 근거 |
|---|---|---|---|
| C1 | SQL은 파라미터 바인딩을 쓴다 | 자동 | OWASP A05 · 2025년 신고 통계 ² |
| C2 | 업로드는 확장자 허용 목록, 서버 생성 파일명, webroot 밖 저장, 크기 제한, 인증을 갖춘다 | 자동+수동 | OWASP 업로드 ⁷ · 개인정보위 판단 사례 ⁴ |
| C3 | 업로드 경로에서 파일이 실행되지 않는다 | 수동 | 개인정보위 판단 사례 ⁴ |

## D. 공급망과 CI
| ID | 점검 | 방식 | 근거 |
|---|---|---|---|
| D1 | 잠금 파일을 커밋하고 CI에서 `npm ci`를 쓴다 | 자동 | npm 문서 ⁸ |
| D2 | 설치 스크립트를 필요한 곳에만 허용한다(`ignore-scripts` 시험 후 적용) | 자동 | npm 문서 ⁸ · 웜 분석 ⁹ |
| D3 | 액션을 전체 SHA로 고정하고 `GITHUB_TOKEN`은 읽기 기본이다 | 자동 | GitHub 문서 ¹⁰ |
| D4 | `pull_request_target`에서 신뢰할 수 없는 코드를 체크아웃하지 않고, `github.event` 값을 `run`에 직접 넣지 않는다 | 자동 | GitHub 문서 ¹⁰ |
| D5 | 토큰 침해 시 해당 사건의 공식 순서를 확인한다. 일부 웜은 토큰 폐기 시 삭제 장치가 동작한다고 분석됨 | 운영 | 웜 분석 ⁹ · 보도·분석 |
| D6 | npm 게시는 장기 토큰을 피하고 2FA나 신뢰 게시를 검토한다 | 운영 | GitHub 계획 ¹¹. OpenJS는 신뢰 게시에 신중론 ¹² |

## E. AI 코딩 에이전트
| ID | 점검 | 방식 | 근거 |
|---|---|---|---|
| E1 | 외부인이 쓴 이슈·PR·댓글로 에이전트가 자동 실행되지 않는다 | 자동 | CSA 노트 ¹³ |
| E2 | 에이전트가 닿는 환경의 비밀값은 수명이 짧고 범위가 좁다. 아웃바운드를 제한한다 | 수동 | CSA 노트 ¹³ |
| E3 | 저장소의 에이전트·에디터 자동 실행 파일을 검토한다(`.claude/settings.json`, `.gemini/settings.json`, `.cursor/mcp.json`, `.vscode/tasks.json`, `.github/init.js`) | 자동 | JFrog 분석 인용 ⁹ · 보도·분석 |
| E4 | 에이전트 도구를 최신으로 유지한다 | 운영 | CSA 노트 ¹³ |

## F. 비밀번호와 암호
| ID | 점검 | 방식 | 근거 |
|---|---|---|---|
| F1 | 비밀번호는 Argon2id(권장 최소 m=19456, t=2, p=1) 또는 scrypt(N=2^17, r=8, p=1), 레거시 bcrypt(work factor 10 이상)로 저장한다. MD5, SHA-1 단독 금지 | 자동 | OWASP 비밀번호 ¹⁴ · 결정문 분석 ³ |
| F2 | TLS 인증서 검증을 끄지 않는다 | 자동 | OWASP A04 · 표준 |

## G. 구조, 탐지, 운영
| ID | 점검 | 방식 | 근거 |
|---|---|---|---|
| G1 | 관계사·부가 서비스 서버에서 회원 DB로 가는 경로가 최소다 | 수동 | 개인정보위 판단 사례 ⁴ |
| G2 | 대량 조회, 비정상 접속에 알림과 차단이 있다 | 수동 | OWASP A09 · 개인정보위 판단 사례 ¹ |
| G3 | 알림마다 담당자와 확인 기한이 있다 | 운영 | 개인정보위 판단 사례 ⁴ |
| G4 | 접속기록을 보관하고 조사 중 삭제하지 않는다. 보관 기간은 법령 원문 확인 | 운영 | 안전성 확보조치 기준 ¹⁵ · 원문 확인 필요 |
| G5 | 패치 담당자와 주기가 있다 | 운영 | OWASP A03 |
| G6 | 사고 시 신고·통지 절차를 미리 정한다 | 운영 | 법률 전문가 확인 필요 |

## 출처
OWASP Top 10:2025 https://top10.owasp.org/2025
1. 개인정보위 판단 보도(소송 중, 법원 판단 전 · 2026-11-02 기준): https://www.ddaily.co.kr/page/view/2026061110411439721 , 소송: https://www.fnnews.com/news/202610081700017140
2. 2025년 신고 통계: https://news.nate.com/view/20260515n28813
3. 개인정보위 결정문 유출 경위 분석: https://datalaw.kr/sanctions/breach/
4. 개인정보위 판단 보도(불복 여부 미확인): https://www.etoday.co.kr/news/view/2641639 , https://www.sankyungtoday.com/news/articleView.html?idxno=63929
5. Supabase RLS: https://supabase.com/docs/guides/database/postgres/row-level-security
6. Vercel 공지: https://vercel.com/kb/bulletin/vercel-april-2026-security-incident
7. OWASP 파일 업로드: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
8. npm ci: https://docs.npmjs.com/cli/v11/commands/npm-ci
9. npm 웜 보도·분석(삭제 동작은 소스 독립 검증 없음): https://www.theregister.com/security/2026/10/26/worm-armed-42-github-repos-by-hiding-a-payload-too-big-to-fail/5305570 , https://corgea.com/research/testmetest-iobandamwer-npm-native-addon-armed-github-repos-october-2026
10. GitHub Actions 보안: https://docs.github.com/en/actions/reference/security/secure-use
11. GitHub npm 계획: https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/
12. OpenJS: https://openjsf.org/blog/publishing-securely-on-npm
13. CSA 노트: https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-coding-agent-ci-prompt-injection-202608/
14. OWASP 비밀번호: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
15. 고시 원문: https://www.law.go.kr/행정규칙/개인정보의안전성확보조치기준 (조문은 이번 조사에서 원문 확인 못 함)
