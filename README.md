# SQL Injection Lab

A small Flask app for teaching how SQL injection works and how parameterized queries prevent it. Each route in `app.py` demonstrates a different vulnerability (or its fix).

## Prerequisites

- Python 3.10+
- MariaDB running locally on port `3306`

## Install MariaDB

Windows (via winget):

```sh
winget install MariaDB.Server
```

macOS (via Homebrew):

```sh
brew install mariadb
brew services start mariadb
```

Debian/Ubuntu:

```sh
sudo apt install mariadb-server
sudo systemctl start mariadb
```

# Setup

Create and activate a virtualenv:

```sh
python -m venv .venv
```
## Activate the environment
### Windows
```
.venv\Scripts\activate
```
### macOS / Linux
```
source .venv/bin/activate
```

## Install Python dependencies:

```sh
pip install flask pymysql
```

Seed the database (creates the `level1` DB, the `users` table, and the `labuser` account used by the app):

```sh
sudo mariadb < seed.sql
```

# Run

```sh
flask --app app run
```

Then open <http://127.0.0.1:5000/> and pick a level.

# Levels

| Path    | Scenario                                                        |
|---------|-----------------------------------------------------------------|
| `/1`    | Classic login bypass (`admin' -- `)                             |
| `/1.2`  | Same bug, password checked first — comments no longer work      |
| `/2`    | Password checked in Python — bypass via `UNION SELECT`          |
| `/safe` | Fixed version using parameterized queries                       |
