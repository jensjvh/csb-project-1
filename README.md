# Cyber Security Base 2025 Project I

Project I for University of Helsinki Cyber Security Base 2025 course.

## Installation and launching locally

* Install [uv](https://docs.astral.sh/uv/#installation) and Python 3.12. (Alternatively, all the requirements are listed in the file [requirements.txt](./requirements.txt))
* Apply the db migrations with `uv run python manage.py migrate` (or `python manage.py migrate`).
* Run the web application locally with Django's server manager [manage.py](./manage.py). To run this with uv while installing all requirements, run the command `uv run python manage.py runserver`.
* The application will launch on port 8000 by default.
