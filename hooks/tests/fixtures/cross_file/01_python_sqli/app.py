"""Primary file: accepts user input and passes to imported db module."""

from .db import run_query


def handle_request(request):
    username = request.form["username"]
    results = run_query(f"SELECT * FROM users WHERE name = '{username}'")
    return results
