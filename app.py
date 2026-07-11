import inspect
import logging

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
        "label": "safe",
        "path": "/safe",
        "name": "Fixed — Parameterized Query",
        "exploit": "username = admin' --      (try it — it no longer works)",
        "reveals": "The fix: user input is bound to %s placeholders instead of being "
                   "formatted into the SQL string, so injection payloads are escaped "
                   "and treated as literal text. The page shows the bound query.",
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



@app.route('/safe')
def safe_login():
    submitted = 'username' in request.args
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    # Parameterized query: the values are sent to the DB separately from the
    # SQL text and bound to the %s placeholders, so input can never change the
    # query structure. This closes the injection entirely.
    query = "SELECT * FROM users WHERE username = %s AND password = %s"
    print(query)
    user = None
    error = None
    bound_query = None
    if submitted:
        try:
            conn = get_db_connection("lab")
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            # The values are passed to execute() separately from the SQL text and
            # bound to the %s placeholders, so input can never change the query.
            bound_query = cursor.mogrify(query, (username, password))
            cursor.execute(query, (username, password))
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            if rows:
                user = rows[0]
        except Exception as e:
            error = str(e)
            logger.error("SQL error: %s", e)

    return render_template('safe.html',
                           submitted=submitted,
                           username=username,
                           password=password,
                           bound_query=bound_query,
                           user=user,
                           error=error,
                           code=inspect.getsource(safe_login))

if __name__ == '__main__':
    app.run()
