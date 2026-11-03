# Cyber Guard Pro

A small Python/Flask security utility prototype with a cryptographically secure password generator, a rule-based password-strength check, and optional URL submission to VirusTotal.

## Features
- Password generation using Python's `secrets` module.
- Transparent rule-based strength assessment (length, case, digits and symbols). This is a heuristic, not a guarantee that a password is safe.
- Optional VirusTotal URL submission using the official API. The endpoint submits a URL for analysis and returns the analysis ID; it does not claim a verdict until analysis results are retrieved separately.

## Run locally
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # optional; set your VirusTotal API key
python app.py
```
Open http://127.0.0.1:5001.

## Docker
```bash
cp .env.example .env
# Add your own VIRUSTOTAL_API_KEY to .env if you want URL submission
docker compose up --build
```

## Tests
```bash
python -m unittest discover -s tests -v
```

## Safety and privacy
- Never test a password that you currently use for an account.
- Never commit `.env` or expose API keys in screenshots or logs.
- Only submit URLs you are authorized to check.
- VirusTotal submissions may share the URL with the service and its partners; review its terms before submitting sensitive URLs.

## Tech stack
Python, Flask, requests, VirusTotal API, HTML, CSS, JavaScript, Docker.
