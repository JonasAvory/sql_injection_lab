import inspect
import logging

import mysql.connector
import pymysql
from flask import Flask, render_template, request

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("sqli_lab")

app = Flask(__name__)


def get_db_connection(database):
    return pymysql.connect(
        host="127.0.0.1",
        port=3306,
        user="labuser",
        password="labpass",
        database=database,
        cursorclass=pymysql.cursors.Cursor,
    )


def run_query(query):
    conn = get_db_connection("lab")
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute(query)
    results = cursor.fetchall()
    cursor.close()
    conn.close()
    return results


LEVELS = [
    {
        "label": "1",
        "path": "/1",
        "name": "Login Bypass",
        "exploit": "username = admin' -- ",
        "reveals": "Authenticate as admin with no password, then leak that "
                   "account's private data (IBAN).",
    },
    {
        "label": "1.2",
        "path": "/1.2",
        "name": "Login Bypass (password checked first)",
        "exploit": "username = a' OR username = 'bob     (admin' --  fails here; "
                   "OR '1'='1 just returns row 0)",
        "reveals": "The password is compared BEFORE the username, so comments won't work.\n"
                   "Try to authenticate as admin.",
    },
    {
        "label": "2",
        "path": "/2",
        "name": "Login Bypass with Password Check",
        "exploit": "username = ' UNION SELECT 1,'x','passwd','admin','',1",
        "reveals": "The Password is now checked by the python code, so you can't exploit this - or can you?",
    },
    {
        "label": "3",
        "path": "/3",
        "name": "Boolean-based Blind Injection",
        "exploit": "username = admin' AND SUBSTRING(password,1,1)='s' -- ",
        "reveals": "The page never shows row data now — only Access granted/denied.\n"
                   "That single bit is still enough: ask true/false questions about "
                   "admin's password one character at a time and rebuild it.",
    },
    {
        "label": "safe",
        "path": "/safe",
        "name": "Fixed — Parameterized Query",
        "exploit": "username = admin' AND SUBSTRING(password,1,1)='s' --      (try it — it no longer works)",
        "reveals": "The fix for the boolean-blind level: user input is bound to %s "
                   "placeholders instead of being formatted into the SQL string, so "
                   "injection payloads are escaped and treated as literal text. The "
                   "page shows the bound query.",
    },
]


@app.route('/')
def index():
    return render_template('index.html', levels=LEVELS)


@app.route('/1')
def login_bypass():
    submitted = 'username' in request.args
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(query)
    rows = []
    columns = []
    error = None
    if submitted:
        try:
            rows = run_query(query)
            # Render whatever comes back generically: the column headers are taken
            # from the result itself, so a UNION SELECT against information_schema
            # (table names, column names, ...) is printed just like normal rows.
            if rows:
                columns = list(rows[0].keys())
        except Exception as e:
            error = str(e)
        logger.error("SQL error: %s", e)

    return render_template('level1.html',
                           submitted=submitted,
                           username=username,
                           password=password,
                           query=query,
                           rows=rows,
                           columns=columns,
                           error=error,
                           code=inspect.getsource(login_bypass))


@app.route('/1.2')
def login_bypass_reordered():
    submitted = 'username' in request.args
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    # Same vulnerability as level 1, but password is compared before username.
    query = f"SELECT * FROM users WHERE password = '{password}' AND username = '{username}'"
    print(query)
    rows = []
    columns = []
    error = None
    if submitted:
        try:
            rows = run_query(query)
            # Generic rendering: headers come from the result, so a UNION SELECT
            # against information_schema is printed just like normal rows.
            if rows:
                columns = list(rows[0].keys())
        except Exception as e:
            error = str(e)
        logger.error("SQL error: %s", e)

    return render_template('level1_2.html',
                           submitted=submitted,
                           username=username,
                           password=password,
                           query=query,
                           rows=rows,
                           columns=columns,
                           error=error,
                           code=inspect.getsource(login_bypass_reordered))


@app.route('/2')
def login_bypass_union():
    submitted = 'username' in request.args
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    # SQL only looks the user up by name; the password is verified in app code.
    query = f"SELECT * FROM users WHERE username = '{username}'"
    print(query)
    user = None
    error = None
    if submitted:
        try:
            rows = run_query(query)
            if rows and rows[0].get('password') == password:
                user = rows[0]
        except Exception as e:
            error = str(e)
            logger.error("SQL error: %s", e)

    return render_template('level2.html',
                           submitted=submitted,
                           username=username,
                           password=password,
                           query=query,
                           user=user,
                           error=error,
                           code=inspect.getsource(login_bypass_union))


@app.route('/2/delete', methods=['POST'])
def delete_website():
    # Demo only: nothing is actually deleted, we just log the action.
    logger.info("starting website deletion...")
    return render_template('level2_delete.html',
                           log_line="starting website deletion...")


@app.route('/3')
def login_bypass_blind():
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    # Same injectable string-building as level 1, but the response below
    # only ever reveals granted/denied — never row data or the raw SQL
    # error — so the only usable signal is that single boolean.
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(query)
    granted = False
    error = None
    try:
        rows = run_query(query)
        granted = bool(rows)
    except Exception as e:
        error = str(e)
        logger.error("SQL error: %s", e)

    return render_template('level3.html',
                           username=username,
                           password=password,
                           query=query,
                           granted=granted,
                           error=error,
                           code=inspect.getsource(login_bypass_blind))


@app.route('/safe')
def safe_login():
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    # A real server-side prepared statement. This query text - still with %s
    # placeholders, never string-formatted - is sent to MariaDB and parsed
    # EXACTLY ONCE via COM_STMT_PREPARE. username/password are then sent
    # afterwards, separately, as typed binary values via COM_STMT_EXECUTE.
    # The server has already finished parsing the query before it ever sees
    # the parameter bytes, so there is no SQL text for an injection payload
    # to reshape - unlike PyMySQL's %s, which is substituted into the query
    # string on the client before it's sent.
    # https://mariadb.com/docs/server/reference/clientserver-protocol/3-binary-protocol-prepared-statements/com_stmt_prepare
    # https://mariadb.com/docs/server/reference/clientserver-protocol/3-binary-protocol-prepared-statements/com_stmt_execute
    query = "SELECT * FROM users WHERE username = %s AND password = %s"
    print(query)
    granted = False
    error = None
    stmt_stats = None
    try:
        conn = mysql.connector.connect(
            host="127.0.0.1",
            port=3306,
            user="labuser",
            password="labpass",
            database="lab",
        )
        status_cursor = conn.cursor()

        def com_stmt_counts():
            # These are MariaDB's own per-connection command counters - proof,
            # not just a claim, that a COM_STMT_PREPARE/COM_STMT_EXECUTE pair
            # actually happened on the wire for this request.
            # https://mariadb.com/kb/en/server-status-variables/#com_stmt_prepare
            status_cursor.execute("SHOW SESSION STATUS LIKE 'Com\\_stmt\\_%'")
            return {name: int(str(value)) for name, value in status_cursor.fetchall()}

        before = com_stmt_counts()
        cursor = conn.cursor(prepared=True)
        cursor.execute(query, (username, password))
        rows = cursor.fetchall()
        cursor.close()
        after = com_stmt_counts()

        status_cursor.close()
        conn.close()
        granted = bool(rows)
        stmt_stats = {
            "Com_stmt_prepare": (before["Com_stmt_prepare"], after["Com_stmt_prepare"]),
            "Com_stmt_execute": (before["Com_stmt_execute"], after["Com_stmt_execute"]),
        }
    except Exception as e:
        error = str(e)
        logger.error("SQL error: %s", e)

    return render_template('safe.html',
                           username=username,
                           password=password,
                           query=query,
                           granted=granted,
                           error=error,
                           stmt_stats=stmt_stats,
                           code=inspect.getsource(safe_login))

if __name__ == '__main__':
    app.run()
