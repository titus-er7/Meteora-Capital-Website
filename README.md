# Meteora-Capital-LLC-Website

## Running the site

The site is served by a small Flask app in `server/`, which also runs the
investor portal on `investors.html`:

1. An investor requests access by completing the accredited investor attestation.
2. The approvers in `MAIL_TO` get an email with a one-time review link, where they
   approve or deny the request.
3. Approved investors are emailed a one-time link to set a password.
4. Investors sign in to see the DocSend links for the deck and latest tear sheet.

```sh
python3 -m venv .venv
.venv/bin/pip install -r server/requirements.txt
cp server/.env.example server/.env   # then fill it in
set -a; . server/.env; set +a
```

Local development (http, so the cookie can't be Secure):

```sh
COOKIE_SECURE=false .venv/bin/python server/app.py   # http://127.0.0.1:8000
```

Production, behind an HTTPS reverse proxy:

```sh
.venv/bin/gunicorn --chdir server --workers 1 --bind 127.0.0.1:8000 "app:create_app()"
```

Keep one worker: rate limits are held in memory. Investors and attestation
records are stored in SQLite (`server/instance/portal.db` by default); back
that file up. Email must be configured in production; without `SMTP_HOST`,
emails (including review and password links) are only printed to the log.

Admin commands:

```sh
.venv/bin/python server/manage.py list            # investors and their status
.venv/bin/python server/manage.py revoke EMAIL    # remove access immediately
```
