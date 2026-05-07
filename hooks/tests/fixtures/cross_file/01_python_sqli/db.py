"""Imported module: executes raw SQL without parameterization."""

import sqlite3


def run_query(sql):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(sql)
    return cursor.fetchall()
