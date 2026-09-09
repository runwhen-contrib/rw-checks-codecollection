# Fake credentials for secret-scanner fixtures. Deliberately non-functional.
#
# The Slack-shaped token that used to be here was rejected by GitHub's own
# push protection: xoxb- tokens carry no checksum, so any correctly shaped
# string matches a partner pattern. The GitHub PAT below is fine for the same
# reason inverted -- real PATs carry a checksum this one fails, so GitHub
# ignores it while gitleaks/trufflehog still match on shape.
GITHUB_TOKEN = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

# Matches gitleaks' generic-api-key rule (keyword + high-entropy value)
# without resembling any provider's partner pattern.
DATABASE_PASSWORD = "kJ8xQ2mN5pR7tV9wY1zA3bC6dE0fG4hI"
DEBUG=True
