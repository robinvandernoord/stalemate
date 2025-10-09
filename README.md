# Stalemate

[![Check Repository Staleness](https://github.com/robinvandernoord/stalemate/actions/workflows/check-repos.yml/badge.svg)](https://github.com/robinvandernoord/stalemate/actions/workflows/check-repos.yml)

*Don't let your repositories reach a stalemate – keep them in play!*

Automatically monitor all your public GitHub repositories for staleness and Python version compatibility. Perfect for maintainers with many small, stable packages that don't need frequent updates but should still be maintained.

## Features

- **Auto-discovers** all your public repos via GitHub API (no manual lists)
- **Detects stale repositories** based on last commit date
- **Checks Python version support** against the latest Python version
- **Smart filtering** (skips archived repos and forks)
- **Runs on GitHub Actions** (no hosting required)

## Setup

1. **Fork this repository**
2. **Edit `config.toml`** with your settings:
   ```toml
   # Your GitHub username to monitor
   github_username = "your-username"
   
   # Days without commits before considering a repo stale
   max_age_days = 365
   
   # Only check repositories with pyproject.toml (Python packages)
   python_only = true
   
   # Check if repos support the latest Python version
   check_python_version = true
   
   # Optional: specific repositories to skip
   exclude_repos = []
   
   # Skip forked repositories
   exclude_forks = true
   ```
3. **Optionally customize** the schedule in `.github/workflows/check-repos.yml` (defaults to 3 AM UTC daily)
4. **Push changes** – the workflow runs automatically

Stale repos will cause the workflow to fail, which may trigger notifications depending on your GitHub notification settings. Outdated Python version classifiers are reported but don't cause failures.

## Local Testing

Create a personal access token at https://github.com/settings/personal-access-tokens/new and add it to a `.env` file or export it:

```bash
export GITHUB_TOKEN=ghp_your_token_here
uv run check_repos.py
```

Requires [uv](https://github.com/astral-sh/uv) installed locally (it will handle Python installation automatically).