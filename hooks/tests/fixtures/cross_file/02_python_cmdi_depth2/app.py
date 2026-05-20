"""Primary file: user input flows through service layer to command execution."""

from .service import process_file


def handle_upload(request):
    filename = request.form["filename"]
    process_file(filename)
