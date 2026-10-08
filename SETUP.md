# Sentinel Evidence — Setup & Run Guide

## Prerequisites

| Tool       | Minimum Version | Check Command       |
| ---------- | --------------- | ------------------- |
| Python     | 3.10+           | `python --version`  |
| Node.js    | 18+             | `node --version`    |
| npm        | 8+              | `npm --version`     |
| Ollama     | (optional)      | `ollama --version`  |

## First-Time Setup

### Windows
```
setup.bat
```

### Linux / macOS
```
chmod +x setup.sh start.sh stop.sh
./setup.sh
```

This will:
1. Check Python, Node.js, and npm.
2. Create a `.venv` virtual environment.
3. Install Python and frontend dependencies.
4. Copy `.env.example` to `.env`.
5. Check Ollama + Gemma model availability.

## Start the Application

### Windows
```
start.bat
```

### Linux / macOS
```
./start.sh
```

This will:
1. Start the FastAPI backend on `http://localhost:8000`.
2. Start the React/Vite frontend on `http://localhost:5173`.
3. Open the application in your default browser.

## Stop the Application

### Windows
```
stop.bat
```

### Linux / macOS
```
./stop.sh
```

## URLs

| Service    | URL                           |
| ---------- | ----------------------------- |
| Frontend   | http://localhost:5173          |
| Backend    | http://localhost:8000          |
| API Docs   | http://localhost:8000/docs     |
| Health     | http://localhost:8000/health   |

## Logs

Backend and frontend logs are stored in `.sentinel/`:

- `.sentinel/backend.log`
- `.sentinel/frontend.log`

## Ollama (Optional AI)

Sentinel Evidence works in **deterministic-only mode** without Ollama.

To enable AI explanations:
1. Install Ollama: https://ollama.com
2. Pull a model: `ollama pull gemma3`
3. Set `OLLAMA_MODEL=gemma3` in `.env`

The setup/start scripts will report Ollama status but **never download models automatically**.

## Troubleshooting

| Problem                    | Solution                                      |
| -------------------------- | --------------------------------------------- |
| Port 8000/5173 in use      | Run `stop.bat` / `stop.sh` first              |
| "Run setup first" error    | Run `setup.bat` / `setup.sh`                  |
| Backend won't start        | Check `.sentinel/backend.log`                 |
| Frontend won't start       | Check `.sentinel/frontend.log`                |
| Python not found           | Install Python 3.10+ and add to PATH          |
| Node.js not found          | Install Node.js 18+ and add to PATH           |
| pip install fails          | Try: `.venv\Scripts\pip install -e ".[test]"`  |
