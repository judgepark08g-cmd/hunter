# hunter
웹 API트래픽을 시각화하고, 데이터 유출 가능성을 자동으로 알려주는 chrome devtools (크롬 확장기능) 입니다.
(Hunter is a Chrome DevTools extension designed to visualize web API traffic and automatically alert you to potential data leaks.)

## 사용법
- F12 버튼을 누른후 상단 텝 메뉴(Network, Consloe 등) 오른쪽 끝에있는 >> 아이콘을 클릭후 Hunter를 누르면 실행이 됩니다.
- Instruction: After pressing the F12 key, click the >> (More tabs) icon at the far right of the top menu bar (next to Network, Console, etc.), then select Hunter to launch the tool.
  
## 왜 이 도구가 필요한가요? (Why Hunter?)
chrome의 network 탭은 강력하지만
- 토큰이나 API key가 노출된 것인지 판단해주지 않고
- 요청을 다시 테스트하거나 API구조를 한눈에 정리해주지 않습니다.
- While Chrome's native Network tab is powerful, it lacks certain specialized features:
- It doesn't automatically identify exposed tokens or API keys.
- It's not optimized for re-testing requests or summarizing complex API structures at a glance.

## 주요기능(Key Features)
- API 요청/응답 트래픽 시각화
- 토큰, 키 등 민감 데이터 노출 가능성 자동감지
- 요청 데이터 수정 후 재실행
- API 요청을 기반으로 한 문서 생성(swagger)
- 분석 결과 기포트 다운로드
- API Traffic Visualization: Clear visualization of request and response flow.
- Sensitive Data Detection: Automatic alerts for exposed tokens, keys, and other sensitive information.
- Request Tampering: Modify and replay requests directly within the tool.
- Auto-Documentation: Generate API documentation (Swagger) based on captured requests.
- Report Export: Download comprehensive analysis reports.

## 개인정보 및 보안(Privacy & Security)
- 네트워크 데이터를 외부로 전송하지 않습니다
- 모든 분석은 브라우저 내부에서만 처리 됩니다
- 로그인, 추적, 사용자 데이터 수집을 하지 않습니다.
- No External Data Transfer: All network data stays within your local environment.
- Local Processing: All analysis is performed entirely inside your browser.
- No Tracking: We do not require logins, nor do we collect any user data.

## 누가 사용하면 좋을까요?(Who Is It For?)
- 웹/백엔드 개발자
- API 테스트 및 디버깅이 필요한사람
- 보안을 공부하는 학생
- 스타트업 또는 개인 프로젝트 개발자
- Web & Backend Developers looking for efficient debugging.
- Anyone needing to test and debug APIs quickly.
- Students studying web security and data privacy.
- Startups or Indie Developers managing personal projects.
  
## 설치방법(Installation)
- 상단에 날짜가 적힌 파일을 다운로드 합니다
- chrome -> 확장프로그램 -> 개발자모드 활성화 -> "압축해제된 확장 프로그램 로드" 선택 -> 폴더 업로드
- Download the file.
- Open Chrome and navigate to chrome://extensions/
- Enable "Developer mode" in the top right corner.
- Click "Load unpacked" and select the downloaded folder.
  
## 후원
이프로젝트는 "학생 개발자가 개인적으로 개발 및 유지보수" 하고있습니다.
도움이 되었다면 후원으로 응원해주세요.
카카오 뱅크 7777-03-4195884  (박재성)
This project is personally developed and maintained by a student developer.If Hunter has been helpful to you, please consider supporting the project:
- bank: KakaoBank (South Korea)
- Account: 7777-03-4195884
- name : 박재성 
