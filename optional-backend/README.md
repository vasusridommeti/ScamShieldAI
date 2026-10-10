# ScamShield AI: Optional Java Backend

This backend is **optional**. The main app (`../index.html`) works completely on its own and does not call this service.

It exposes the same 14 rules as the browser app through a small REST API, which is a starting point for future integrations (for example an optional language-model explanation step).

## Test status (please read)
- The detection class `ScamAnalysisService` was compiled with `javac` and run on the sample messages. Its scores matched the JavaScript engine exactly.
- The full Spring Boot project (`pom.xml`, controller, startup) was **not built or run** during development, because the development sandbox could not download Maven dependencies. Please build it once on your own laptop before presenting it live.

## Prerequisites (Windows 10/11)
- JDK 17 or newer. Check with `java -version`.
- Apache Maven 3.9 or newer. Check with `mvn -v`.
- Internet access for the first build (to download dependencies).

## Run (PowerShell)
```powershell
cd path\to\ScamShield-AI\optional-backend
mvn spring-boot:run
```
The API starts on http://localhost:8080.

Or build a jar:
```powershell
mvn clean package
java -jar target\scamshield-backend-1.0.0.jar
```

## Endpoints
`GET /api/health`
```powershell
curl.exe http://localhost:8080/api/health
```

`POST /api/analyze`
```powershell
curl.exe -X POST http://localhost:8080/api/analyze -H "Content-Type: application/json" -d "{\"message\":\"Your account will be blocked in 10 minutes. Reply with your OTP to avoid suspension.\"}"
```
Response (shortened):
```json
{ "score": 72, "level": "high", "findings": [ { "id": "SS-001", "weight": 40, "phrase": "Reply with your OTP" } ], "safeAdviceDetected": false, "length": 84, "disclaimer": "..." }
```
Errors return HTTP 400 with `{ "error": "..." }` for empty messages or messages over 5,000 characters.

## Privacy and deployment notes
- Messages are processed in memory, never logged and never stored. Do not add request-body logging.
- The browser app does not use this API, so enabling it would be a deliberate change that sends message text to your server. Tell users, and use HTTPS if deployed.
- CORS is limited to the origins in `application.properties` (`scamshield.allowed-origins`).
- Add authentication and rate limiting before any public deployment.
- Input is validated (non-empty, at most 5,000 characters) and error details are not leaked.
