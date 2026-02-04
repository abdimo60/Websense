# WebSense

WebSense checks whether a link is safe to open.

## Live Prototype
https://YOUR-RENDER-URL

Paste a link and click **Check link**. No login required.

## Assessor Access
- Publicly accessible
- No credentials required

## API
POST /api/scan/

Example:
{
  "url": "https://example.com"
}

## Code
https://github.com/abdimo60/Websense

## Local Run
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver

## Notes
- Hosted externally due to submission timeframe
- API keys stored as environment variables
- Scan data stored in SQLite
