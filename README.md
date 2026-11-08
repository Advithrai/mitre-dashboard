# APT Technique & Candidate Group Dashboard

A local, password-protected dashboard for the Windows-APT 2025 project.
Upload a Wazuh alert CSV and it shows:

1. **Overview** – what is in the file
2. **Techniques** – the model's top-3 MITRE ATT&CK technique guesses per attack command
3. **Why? (SHAP)** – which clues pushed the model towards its answer
4. **Candidate groups** – threat groups whose technique lists fit, with reasons and warnings
5. **Simulation** – the semi-synthetic ranking test, live
6. **About** – what the scores mean and what they do not mean

## Folder layout

```
dashboard/
  app.py                  the dashboard
  pipeline.py             alerts -> model inputs (verified 100% against the notebook, cell 19)
  ranker.py               Jaccard and weighted Jaccard group ranking (notebook cell 13)
  explain.py              exact SHAP for the linear model (notebook cell 18)
  auth.py                 login
  make_password_hash.py   makes the hashed password
  requirements.txt
  demo_upload_two_days.csv.gz   made by notebook cell 21
  .streamlit/
    config.toml           security settings (localhost only, upload limit)
    secrets.toml          your username + hashed password  (never share)
  models/                 made by notebook cells 19 and 21
    final_model.joblib, final_model_info.json, shap_background_mean.npy,
    group_profiles.csv, rule_descriptions.csv, technique_names.csv,
    pipeline_settings.json
```

## How to run (Windows)

Open **Anaconda Prompt** (or the terminal you use for Jupyter), then:

1. Go to the folder:
   ```
   cd C:\Users\Advith\Documents\ics_attribution_project\windows_apt_2025\dashboard
   ```
2. Install the libraries (once), in the same Python environment as the notebook:
   ```
   pip install -r requirements.txt
   ```
3. Set up the login (once):
   ```
   python make_password_hash.py
   ```
   Copy `.streamlit\secrets.toml.example` to `.streamlit\secrets.toml`,
   choose a username, and paste the printed `password_hash = "..."` line.
4. Start the dashboard:
   ```
   streamlit run app.py
   ```
   It opens at http://localhost:8501. Log in and upload
   `demo_upload_two_days.csv.gz`.

Stop it with **Ctrl + C** in the terminal.

## Security

- Password login; only a bcrypt hash of the password is stored.
  5 wrong tries lock the login for 60 seconds.
- Runs on `localhost` only: other computers cannot reach it.
- Upload: `.csv` or `.csv.gz` only, at most 100 MB (`config.toml`),
  at most 300,000 rows, at most 600 MB after unzipping.
- Uploads stay in memory for the current browser session and are never
  written to disk. Logging out forgets them.
- Errors show a plain message, not the program's internals.
- The prediction download contains no command text.

## Honest-use notes

- Demo days come from the training data, so guesses on them look better than
  the measured scores. Quote the measured scores (About tab).
- Group scores measure fit, not probability, and the ranking was tested on
  simulated attacks. The output is "candidate groups", not the real attacker.
