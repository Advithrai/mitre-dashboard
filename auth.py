"""
auth.py  -  the login page

WHY: only people who know the password can see the dashboard.
The real password is never stored. Only its bcrypt "hash" is stored in
.streamlit/secrets.toml. A hash is a one-way scramble: you can check a typed
password against it, but you cannot turn it back into the password.
Make the hash with make_password_hash.py.

After 5 wrong tries the login is locked for 60 seconds, to slow down guessing.
"""
from __future__ import annotations

import hmac
import time

import bcrypt
import streamlit as st

MAX_TRIES = 5
LOCK_SECONDS = 60


def _settings():
    try:
        return st.secrets["auth"]["username"], st.secrets["auth"]["password_hash"]
    except Exception:
        st.error("Login is not set up. Create .streamlit/secrets.toml with an [auth] section "
                 "(see README.md, step 3).")
        st.stop()


def check_login() -> bool:
    """Show the login form until the user logs in. Returns True when logged in."""
    if st.session_state.get("logged_in"):
        return True

    username, pw_hash = _settings()
    st.title("APT Technique & Candidate Group Dashboard")
    st.caption("Please log in to continue.")

    locked_until = st.session_state.get("locked_until", 0.0)
    if time.time() < locked_until:
        st.error(f"Too many wrong tries. Wait {int(locked_until - time.time()) + 1} seconds.")
        st.stop()

    with st.form("login"):
        user = st.text_input("Username")
        pw = st.text_input("Password", type="password")
        ok = st.form_submit_button("Log in")

    if ok:
        user_ok = hmac.compare_digest(user.encode(), username.encode())
        try:
            pw_ok = bcrypt.checkpw(pw.encode(), pw_hash.encode())
        except ValueError:
            st.error("The password hash in secrets.toml is not valid. Make it again with "
                     "make_password_hash.py.")
            st.stop()
        if user_ok and pw_ok:
            st.session_state["logged_in"] = True
            st.session_state["tries"] = 0
            st.rerun()
        else:
            tries = st.session_state.get("tries", 0) + 1
            st.session_state["tries"] = tries
            if tries >= MAX_TRIES:
                st.session_state["locked_until"] = time.time() + LOCK_SECONDS
                st.session_state["tries"] = 0
            st.error("Wrong username or password.")
    return False


def logout_button():
    if st.sidebar.button("Log out"):
        # forget everything from this session, including the uploaded data
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()
