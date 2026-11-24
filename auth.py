"""
Login gate for the dashboard (cloud-ready).

Reads the username and the bcrypt password HASH from environment variables
(APP_USERNAME, APP_PASSWORD_HASH). If they are not set, it falls back to
.streamlit/secrets.toml, so it still works on your laptop:

    [auth]
    username = "advith"
    password_hash = "$2b$12$..."

Lockout: after 5 wrong tries, the login is locked for 60 s. Each new lock
doubles the time (max 15 min). The counter is shared by ALL visitors
(not per browser tab), so opening a new tab does not reset it.

app.py calls check_login() and logout_button() (the old names). Both are
provided at the bottom of this file and use require_login() inside.
"""
import hmac
import os
import time

import bcrypt
import streamlit as st

MAX_TRIES = 5
BASE_LOCK_SECONDS = 60
MAX_LOCK_SECONDS = 900

# A fixed fake hash, checked when the username is wrong, so a wrong username
# and a wrong password take the same time (does not leak which one was wrong).
_DUMMY_HASH = bcrypt.hashpw(b"not-the-password", bcrypt.gensalt())


def _get_credentials():
    user = os.environ.get("APP_USERNAME", "").strip()
    pw_hash = os.environ.get("APP_PASSWORD_HASH", "").strip()
    if user and pw_hash:
        return user, pw_hash.encode("utf-8")
    try:  # local fallback
        user = st.secrets["auth"]["username"]
        pw_hash = st.secrets["auth"]["password_hash"]
        return user, pw_hash.encode("utf-8")
    except Exception:
        return None, None


@st.cache_resource
def _tracker():
    # one shared dictionary for the whole server process
    return {"fails": 0, "locked_until": 0.0, "lock_level": 0}


def _check(username, password):
    real_user, real_hash = _get_credentials()
    if real_user is None:
        return False
    user_ok = hmac.compare_digest(username.encode(), real_user.encode())
    try:
        pw_ok = bcrypt.checkpw(password.encode(), real_hash if user_ok else _DUMMY_HASH)
    except ValueError:  # malformed hash
        return False
    return bool(user_ok and pw_ok)


def require_login():
    """Stops the page until login works. Shows a Log out button once logged in."""
    if st.session_state.get("authed"):
        with st.sidebar:
            if st.button("Log out"):
                # forget everything, including the uploaded file and results
                st.session_state.clear()
                st.rerun()
        return

    user, pw_hash = _get_credentials()
    st.title("Sign in")
    if user is None:
        st.error("Login is not configured. Set APP_USERNAME and APP_PASSWORD_HASH.")
        st.stop()

    t = _tracker()
    wait = int(t["locked_until"] - time.time())
    if wait > 0:
        st.warning(f"Too many wrong tries. Please wait {wait} seconds and refresh.")
        st.stop()

    with st.form("login", clear_on_submit=True):
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        go = st.form_submit_button("Sign in")

    if go:
        if _check(u, p):
            t.update(fails=0, lock_level=0, locked_until=0.0)
            st.session_state["authed"] = True
            st.rerun()
        else:
            t["fails"] += 1
            if t["fails"] >= MAX_TRIES:
                lock = min(BASE_LOCK_SECONDS * (2 ** t["lock_level"]), MAX_LOCK_SECONDS)
                t["locked_until"] = time.time() + lock
                t["lock_level"] += 1
                t["fails"] = 0
                st.error(f"Too many wrong tries. Locked for {lock} seconds.")
            else:
                st.error("Wrong username or password.")
    st.stop()


# ---- names used by app.py -------------------------------------------------
def check_login():
    """Old name used by app.py. Stops the page until login works."""
    require_login()
    return True


def logout_button():
    """Old name used by app.py. require_login() already shows the button."""
    pass