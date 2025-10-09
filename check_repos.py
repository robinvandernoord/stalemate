# /// script
# dependencies = [
#     "requests",
#     "packaging",
#     "python-dotenv",
#     "configuraptor",
# ]
# ///

import base64
import datetime as dt
import logging
import os
import sys
import time

import configuraptor
import configuraptor.errors
import requests
import tomllib
from dotenv import load_dotenv
from packaging.specifiers import SpecifierSet
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


class StalemateConfig(configuraptor.TypedConfig):
    # Your GitHub username to monitor
    github_username: str

    # Days without commits before considering a repo stale
    max_age_days: int = 365

    # Only check repositories with pyproject.toml (Python packages)
    python_only: bool = True

    # Check if repos support the latest Python version
    check_python_version: bool = True

    # Optional: specific repositories to skip
    exclude_repos: list[str] = []

    # Skip forked repositories
    exclude_forks: bool = True


class RepoMonitor:
    def __init__(self, verbose: bool = False):
        # Load environment variables from .env file
        load_dotenv()

        self.config = self.load_config()
        self.github_token = os.getenv("GITHUB_TOKEN")

        # Validate that GITHUB_TOKEN is provided
        if not self.github_token:
            print("::error::GITHUB_TOKEN environment variable is required but not set.")
            print(
                "::error::Without a token, GitHub API rate limits (60 requests/hour) make this tool unusable."
            )
            print(
                "::error::Create a personal access token at: https://github.com/settings/personal-access-tokens/new"
            )
            print(
                "::error::Or if running in GitHub Actions, GITHUB_TOKEN is automatically provided."
            )
            sys.exit(1)

        # Setup logging
        self.setup_logging(verbose)

        self.current_python_version = (
            f"{sys.version_info.major}.{sys.version_info.minor}"
        )
        self.session = self.setup_session()

        self.stale_repos: list[dict] = []
        self.python_version_issues: list[dict] = []

        # Rate limiting state
        self.rate_limit_remaining = None
        self.rate_limit_reset = None

    def setup_logging(self, verbose: bool) -> None:
        """Setup logging configuration"""
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.StreamHandler(sys.stdout)],
        )
        self.logger = logging.getLogger(__name__)

    def load_config(self) -> StalemateConfig:
        """Load configuration from config.toml using configuraptor"""
        try:
            return StalemateConfig.load("config.toml")
        except FileNotFoundError:
            raise ValueError("config.toml not found")
        except configuraptor.errors.FailedToLoad:
            raise ValueError(f"config.toml not found or invalid")

    def setup_session(self) -> requests.Session:
        """Set up requests session with retry strategy and custom user agent"""
        session = requests.Session()

        # Set custom user agent
        session.headers.update(
            {
                "User-Agent": "stalemate/1.0",
                "Accept": "application/vnd.github.v3+json",
                "Authorization": f"token {self.github_token}",
            }
        )

        self.logger.info("Using authenticated GitHub API requests")

        retry_strategy = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[403, 429, 500, 502, 503, 504],
            allowed_methods=["GET"],
            respect_retry_after_header=True,
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def handle_rate_limits(self, response: requests.Response) -> None:
        """Update rate limit state from response headers"""
        # Update rate limit information
        remaining = response.headers.get("X-RateLimit-Remaining")
        reset = response.headers.get("X-RateLimit-Reset")

        if remaining is not None:
            self.rate_limit_remaining = int(remaining)
        if reset is not None:
            self.rate_limit_reset = int(reset)

        self.logger.debug(
            f"Rate limit: {self.rate_limit_remaining} remaining, reset at {self.rate_limit_reset}"
        )

        # If we're getting low on requests, wait until reset
        if self.rate_limit_remaining is not None and self.rate_limit_remaining <= 10:
            if self.rate_limit_reset is not None:
                current_time = int(time.time())
                wait_time = (
                    max(0, self.rate_limit_reset - current_time) + 1
                )  # Add 1 second buffer
                if wait_time > 0:
                    self.logger.warning(
                        f"Rate limit low ({self.rate_limit_remaining} remaining). Waiting {wait_time} seconds until reset."
                    )
                    headers = {
                        k: v
                        for k, v in response.headers.items()
                        if k.lower().startswith("x-ratelimit-")
                    }
                    self.logger.debug(f"Rate limit headers: {headers}")
                    time.sleep(wait_time)

    def check_rate_limits_before_request(self) -> None:
        """Check if we need to wait before making a request due to rate limits"""
        if self.rate_limit_remaining is not None and self.rate_limit_remaining <= 0:
            if self.rate_limit_reset is not None:
                current_time = int(time.time())
                wait_time = max(0, self.rate_limit_reset - current_time) + 1
                if wait_time > 0:
                    self.logger.warning(
                        f"Rate limit exhausted. Waiting {wait_time} seconds until reset."
                    )
                    time.sleep(wait_time)
                # Reset the counter after waiting
                self.rate_limit_remaining = None
                self.rate_limit_reset = None

    def safe_api_request(self, url: str, params: dict = None) -> requests.Response:
        """Make API request with proper error handling and rate limiting"""
        self.logger.debug(f"Making request to: {url}")

        # Check if we need to wait due to rate limits
        self.check_rate_limits_before_request()

        response = self.session.get(url, params=params)
        self.logger.debug(f"Response status: {response.status_code}")

        # Handle authentication errors specifically
        if response.status_code == 401:
            self.logger.error("Authentication failed - check GITHUB_TOKEN if provided")

        # Update rate limit state for all responses (not just 200)
        self.handle_rate_limits(response)

        # For 403 responses, provide more detailed information
        if response.status_code == 403:
            rate_limit_remaining = response.headers.get("X-RateLimit-Remaining")
            rate_limit_reset = response.headers.get("X-RateLimit-Reset")
            self.logger.error(
                f"Rate limit exceeded. Remaining: {rate_limit_remaining}, Reset: {rate_limit_reset}"
            )

        response.raise_for_status()
        return response

    def fetch_all_repos(self) -> list[dict]:
        """Fetch all repositories with pagination"""
        repos = []
        page = 1
        per_page = 100

        while True:
            url = f"https://api.github.com/users/{self.config.github_username}/repos"
            params = {
                "type": "owner",
                "page": page,
                "per_page": per_page,
                "sort": "pushed",
                "direction": "desc",
            }

            self.logger.info(f"Fetching page {page} of repositories")
            response = self.safe_api_request(url, params)
            page_repos = response.json()

            if not page_repos:
                self.logger.debug("No more repositories found")
                break

            repos.extend(page_repos)
            self.logger.debug(f"Fetched {len(page_repos)} repositories on page {page}")

            # Check if we've fetched all repos
            if len(page_repos) < per_page:
                self.logger.debug("Last page of repositories reached")
                break

            page += 1
            # Brief pause between pages to be respectful
            time.sleep(0.5)

        self.logger.info(f"Total repositories fetched: {len(repos)}")
        return repos

    def filter_repos(self, repos: list[dict]) -> list[dict]:
        """Filter repositories based on config"""
        filtered = []

        for repo in repos:
            # Skip archived repos
            if repo["archived"]:
                self.logger.debug(f"Skipping archived repo: {repo['name']}")
                continue

            # Skip forks if configured
            if self.config.exclude_forks and repo["fork"]:
                self.logger.debug(f"Skipping fork repo: {repo['name']}")
                continue

            # Skip explicitly excluded repos
            if repo["name"] in self.config.exclude_repos:
                self.logger.debug(f"Skipping excluded repo: {repo['name']}")
                continue

            filtered.append(repo)

        self.logger.info(
            f"Filtered to {len(filtered)} repositories after applying filters"
        )
        return filtered

    def check_pyproject_exists(self, owner: str, repo_name: str) -> str | None:
        """Check if pyproject.toml exists and return its content"""
        url = (
            f"https://api.github.com/repos/{owner}/{repo_name}/contents/pyproject.toml"
        )
        self.logger.debug(f"Checking pyproject.toml for {owner}/{repo_name}")

        try:
            response = self.safe_api_request(url)
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                self.logger.debug(f"pyproject.toml not found in {owner}/{repo_name}")
                return None
            self.logger.error(
                f"Error checking pyproject.toml for {owner}/{repo_name}: {e}"
            )
            raise

        content_data = response.json()
        if content_data.get("encoding") == "base64":
            content = base64.b64decode(content_data["content"]).decode("utf-8")
            self.logger.debug(f"Found pyproject.toml in {owner}/{repo_name}")
            return content

        self.logger.debug(
            f"pyproject.toml found but no base64 content in {owner}/{repo_name}"
        )
        return None

    def parse_python_version(self, pyproject_content: str) -> str | None:
        """Parse Python version requirements from pyproject.toml"""
        try:
            pyproject_data = tomllib.loads(pyproject_content)
        except tomllib.TOMLDecodeError:
            self.logger.warning("Failed to parse pyproject.toml content")
            return None

        requires_python = pyproject_data.get("project", {}).get("requires-python")
        classifiers = pyproject_data.get("project", {}).get("classifiers", [])

        # Extract versions from classifiers
        classifier_versions = []
        for classifier in classifiers:
            if classifier.startswith("Programming Language :: Python ::"):
                parts = classifier.split("::")
                version = parts[-1].strip()
                if version.replace(".", "").isdigit():  # Basic version check
                    classifier_versions.append(version)

        # If we have requires-python with an upper bound, use that
        if requires_python:
            # Check if requires-python has an upper bound (< or <=)
            if any(op in requires_python for op in ["<", "<="]):
                self.logger.debug(
                    f"Using requires-python with upper bound: {requires_python}"
                )
                return requires_python

        # Otherwise, use the maximum classifier version with <= constraint
        if classifier_versions:
            # Sort versions and take the highest
            max_version = max(
                classifier_versions, key=lambda v: tuple(map(int, v.split(".")))
            )
            version_spec = f"<={max_version}"
            self.logger.debug(
                f"Using maximum classifier version with upper bound: {version_spec}"
            )
            return version_spec

        # Fallback to requires-python if no classifiers found
        if requires_python:
            self.logger.debug(
                f"Using requires-python (no classifiers): {requires_python}"
            )
            return requires_python

        self.logger.debug("No Python version specification found")
        return None

    def check_python_version_support(self, version_spec: str, repo_name: str) -> bool:
        """Check if current Python version is supported"""
        try:
            specifier = SpecifierSet(version_spec)
            supported = specifier.contains(self.current_python_version)
            self.logger.debug(
                f"Version {self.current_python_version} supported by {version_spec}: {supported}"
            )
            return supported
        except Exception as e:
            self.logger.warning(
                f"Invalid Python specifier '{version_spec}' for {repo_name}: {e}"
            )
            return True  # Don't fail on parsing errors

    def check_staleness(self, pushed_at: str) -> tuple[bool, int]:
        """Check if repository is stale and return days since last push"""
        pushed_dt = dt.datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
        now = dt.datetime.now(dt.timezone.utc)

        days_since_push = (now - pushed_dt).days
        is_stale = days_since_push > self.config.max_age_days

        self.logger.debug(f"Staleness check: {days_since_push} days, stale: {is_stale}")
        return is_stale, days_since_push

    def process_repository(self, repo: dict) -> None:
        """Process a single repository"""
        repo_name = repo["name"]
        owner = self.config.github_username
        self.logger.info(f"Processing repository: {repo_name}")

        # Check if it's a Python repo if configured
        pyproject_content = None
        if self.config.python_only:
            pyproject_content = self.check_pyproject_exists(owner, repo_name)
            if not pyproject_content:
                self.logger.debug(f"Skipping non-Python repo: {repo_name}")
                return  # Skip non-Python repos

        # Check staleness
        is_stale, days_since_push = self.check_staleness(repo["pushed_at"])
        if is_stale:
            self.stale_repos.append(
                {
                    "name": repo_name,
                    "html_url": repo["html_url"],
                    "days_since_push": days_since_push,
                }
            )
            self.logger.info(
                f"Repository {repo_name} is stale ({days_since_push} days)"
            )

        # Check Python version support if configured and it's a Python repo
        if self.config.check_python_version and pyproject_content:
            version_spec = self.parse_python_version(pyproject_content)
            if version_spec and not self.check_python_version_support(
                version_spec, repo_name
            ):
                self.python_version_issues.append(
                    {
                        "name": repo_name,
                        "html_url": repo["html_url"],
                        "version_spec": version_spec,
                    }
                )
                self.logger.info(
                    f"Python version issue found for {repo_name}: {version_spec}"
                )

    def generate_report(self) -> None:
        """Generate formatted report with GitHub Actions annotations"""
        print("\n" + "=" * 60)

        # Stale repositories section
        if self.stale_repos:
            print(
                f"⚠️  STALE REPOSITORIES (no commits in {self.config.max_age_days}+ days):\n"
            )
            for repo in self.stale_repos:
                print(
                    f"- {repo['name']} (last push: {repo['days_since_push']} days ago)"
                )
                print(f"  {repo['html_url']}")
                print(
                    f"::warning file={repo['name']}::Repository stale for {repo['days_since_push']} days"
                )
                print()
        else:
            print("✅ No stale repositories found!")

        # Python version section
        if self.python_version_issues:
            print(f"ℹ️  PYTHON VERSION UPDATES AVAILABLE:\n")
            for repo in self.python_version_issues:
                print(
                    f"- {repo['name']} (supports: {repo['version_spec']}, current: {self.current_python_version})"
                )
                print(f"  {repo['html_url']}")
                print(
                    f"::notice file={repo['name']}::Python {self.current_python_version} support could be added"
                )
                print()
        elif self.config.check_python_version:
            print("✅ All Python packages support the current version!")

        print("=" * 60)
        print(
            f"Summary: {len(self.stale_repos)} stale repos, {len(self.python_version_issues)} Python version updates available"
        )

    def run(self) -> None:
        """Main execution flow"""
        try:
            # Fetch and filter repositories
            self.logger.info("Fetching repositories...")
            all_repos = self.fetch_all_repos()
            repos = self.filter_repos(all_repos)
            self.logger.info(f"Found {len(repos)} repositories to check")

            # Process each repository
            for repo in repos:
                self.process_repository(repo)

            # Generate report
            self.generate_report()

            # Exit with appropriate code
            exit_code = 1 if self.stale_repos else 0
            self.logger.info(f"Exiting with code: {exit_code}")
            sys.exit(exit_code)

        except requests.RequestException as e:
            self.logger.error(f"API request failed: {e}")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            sys.exit(1)


if __name__ == "__main__":
    # Check for verbose flag
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    monitor = RepoMonitor(verbose=verbose)
    monitor.run()
