"""Investor portal admin commands.

  python server/manage.py list              # all investors and their status
  python server/manage.py revoke EMAIL      # remove access and sign them out

Reads DATABASE_PATH from the environment, like the server.
"""

import sys

from app import connect, init_db, iso, now_utc


def list_investors():
    with connect() as conn:
        rows = conn.execute(
            "SELECT email, full_name, status, password_hash IS NOT NULL AS has_password,"
            " created_at, decided_at FROM investors ORDER BY created_at"
        ).fetchall()
    if not rows:
        print("No investors yet.")
    for r in rows:
        password = "password set" if r["has_password"] else "no password"
        print(f"{r['status']:<9} {r['email']:<40} {r['full_name']:<30} {password:<13} requested {r['created_at']}")


def revoke(email):
    with connect() as conn:
        cur = conn.execute(
            "UPDATE investors SET status = 'revoked', decided_at = ?, session_epoch = session_epoch + 1"
            " WHERE email = ?",
            (iso(now_utc()), email),
        )
        conn.execute(
            "UPDATE tokens SET used_at = ? WHERE used_at IS NULL AND investor_id ="
            " (SELECT id FROM investors WHERE email = ?)",
            (iso(now_utc()), email),
        )
    print(f"Revoked {email}." if cur.rowcount else f"No investor with email {email}.")


def main(argv):
    init_db()
    if argv[1:2] == ["list"]:
        list_investors()
    elif argv[1:2] == ["revoke"] and len(argv) == 3:
        revoke(argv[2])
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
